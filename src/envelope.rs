//! The Wallet File container.
//!
//! ```text
//! 0..6     magic "DRVTR\0"
//! 6        format version
//! 7        kdf id
//! 8..20    Argon2id m_kib, t, p (u32 LE each)
//! 20..36   salt
//! 36..60   wrap nonce
//! 60..108  wrapped data key (32 + 16 tag)
//! 108..132 body nonce
//! 132..    body ciphertext
//! ```

use anyhow::{Result, anyhow, bail};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

const MAGIC: [u8; 6] = *b"DRVTR\0";
const FORMAT_VERSION: u8 = 1;
const KDF_ARGON2ID: u8 = 1;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;
const WRAPPED_LEN: usize = KEY_LEN + TAG_LEN;

const OFF_SALT: usize = 20;
const OFF_WRAP_NONCE: usize = OFF_SALT + SALT_LEN;
const OFF_WRAPPED: usize = OFF_WRAP_NONCE + NONCE_LEN;
const OFF_BODY_NONCE: usize = OFF_WRAPPED + WRAPPED_LEN;
pub const HEADER_LEN: usize = OFF_BODY_NONCE + NONCE_LEN;

/// The prefix the key-encrypting key is bound to. Lowering the Argon2id cost of
/// an existing file changes these bytes and the unwrap then fails.
const KDF_AAD_LEN: usize = OFF_SALT + SALT_LEN;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl KdfParams {
    pub const FAST: Self = Self {
        m_kib: 32 * 1024,
        t: 2,
        p: 1,
    };
    pub const STANDARD: Self = Self {
        m_kib: 256 * 1024,
        t: 4,
        p: 4,
    };
    pub const PARANOID: Self = Self {
        m_kib: 1024 * 1024,
        t: 4,
        p: 4,
    };

    /// A Wallet File names its own work factor, so a hostile one could ask for
    /// terabytes of memory or millions of passes. Refuse before doing the work.
    fn check(&self) -> Result<()> {
        if !(8..=4 * 1024 * 1024).contains(&self.m_kib) {
            bail!("Wallet File asks for {} KiB of Argon2id memory", self.m_kib);
        }
        if !(1..=64).contains(&self.t) || !(1..=64).contains(&self.p) {
            bail!(
                "Wallet File asks for {} Argon2id passes at {} lanes",
                self.t,
                self.p
            );
        }
        Ok(())
    }

    fn derive(&self, passphrase: &SecretString, salt: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
        let params = Params::new(self.m_kib, self.t, self.p, Some(KEY_LEN))
            .map_err(|e| anyhow!("invalid Argon2id parameters: {e}"))?;
        let mut kek = Zeroizing::new([0u8; KEY_LEN]);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(passphrase.expose_secret().as_bytes(), salt, &mut *kek)
            .map_err(|e| anyhow!("key derivation failed: {e}"))?;
        Ok(kek)
    }
}

/// Bound to the body so a file from another format version cannot be replayed
/// into this one. Deliberately excludes the salt and the wrapped key, which
/// `rekey` rewrites while leaving the body alone.
fn body_aad(body_nonce: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(8 + NONCE_LEN);
    aad.extend_from_slice(&MAGIC);
    aad.push(FORMAT_VERSION);
    aad.push(KDF_ARGON2ID);
    aad.extend_from_slice(body_nonce);
    aad
}

fn cipher(key: &[u8]) -> Result<XChaCha20Poly1305> {
    XChaCha20Poly1305::new_from_slice(key).map_err(|_| anyhow!("wrong key length"))
}

fn nonce(bytes: &[u8]) -> Result<XNonce> {
    XNonce::try_from(bytes).map_err(|_| anyhow!("wrong nonce length"))
}

fn seal(key: &[u8], iv: &[u8], msg: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    cipher(key)?
        .encrypt(&nonce(iv)?, Payload { msg, aad })
        .map_err(|_| anyhow!("encryption failed"))
}

fn unseal(key: &[u8], iv: &[u8], msg: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    cipher(key)?
        .decrypt(&nonce(iv)?, Payload { msg, aad })
        .map(Zeroizing::new)
        .map_err(|_| anyhow!("could not decrypt: wrong File Passphrase, or the file is damaged"))
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).map_err(|e| anyhow!("no system randomness available: {e}"))?;
    Ok(buf)
}

fn write_header(
    salt: &[u8],
    wrap_nonce: &[u8],
    wrapped: &[u8],
    body_nonce: &[u8],
    kdf: KdfParams,
) -> Vec<u8> {
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(&MAGIC);
    header.push(FORMAT_VERSION);
    header.push(KDF_ARGON2ID);
    header.extend_from_slice(&kdf.m_kib.to_le_bytes());
    header.extend_from_slice(&kdf.t.to_le_bytes());
    header.extend_from_slice(&kdf.p.to_le_bytes());
    header.extend_from_slice(salt);
    header.extend_from_slice(wrap_nonce);
    header.extend_from_slice(wrapped);
    header.extend_from_slice(body_nonce);
    header
}

/// Wrap a data key under a passphrase-derived key and emit the header bytes.
fn wrap(
    passphrase: &SecretString,
    dek: &[u8],
    body_nonce: &[u8],
    kdf: KdfParams,
) -> Result<Vec<u8>> {
    let salt = random::<SALT_LEN>()?;
    let wrap_nonce = random::<NONCE_LEN>()?;
    let mut header = write_header(&salt, &wrap_nonce, &[0u8; WRAPPED_LEN], body_nonce, kdf);

    let kek = kdf.derive(passphrase, &salt)?;
    let wrapped = seal(&*kek, &wrap_nonce, dek, &header[..KDF_AAD_LEN])?;
    header[OFF_WRAPPED..OFF_BODY_NONCE].copy_from_slice(&wrapped);
    Ok(header)
}

pub fn encrypt(passphrase: &SecretString, plaintext: &[u8], kdf: KdfParams) -> Result<Vec<u8>> {
    let dek = Zeroizing::new(random::<KEY_LEN>()?);
    let body_nonce = random::<NONCE_LEN>()?;

    let header = wrap(passphrase, &*dek, &body_nonce, kdf)?;
    let body = seal(&*dek, &body_nonce, plaintext, &body_aad(&body_nonce))?;

    let mut file = header;
    file.extend_from_slice(&body);
    Ok(file)
}

struct Opened {
    dek: Zeroizing<[u8; KEY_LEN]>,
    kdf: KdfParams,
}

fn parse(file: &[u8]) -> Result<(&[u8], &[u8], KdfParams)> {
    if file.len() < HEADER_LEN + TAG_LEN {
        bail!("not a Wallet File: too short");
    }
    if file[..6] != MAGIC {
        bail!("not a Wallet File: bad magic bytes");
    }
    if file[6] != FORMAT_VERSION {
        bail!(
            "unsupported Wallet File version {} (this build writes {FORMAT_VERSION})",
            file[6]
        );
    }
    if file[7] != KDF_ARGON2ID {
        bail!("unsupported key derivation function id {}", file[7]);
    }
    let word = |at: usize| u32::from_le_bytes([file[at], file[at + 1], file[at + 2], file[at + 3]]);
    let kdf = KdfParams {
        m_kib: word(8),
        t: word(12),
        p: word(16),
    };
    kdf.check()?;
    Ok((&file[..HEADER_LEN], &file[HEADER_LEN..], kdf))
}

fn unwrap_dek(passphrase: &SecretString, header: &[u8], kdf: KdfParams) -> Result<Opened> {
    let kek = kdf.derive(passphrase, &header[OFF_SALT..OFF_WRAP_NONCE])?;
    let plaintext = unseal(
        &*kek,
        &header[OFF_WRAP_NONCE..OFF_WRAPPED],
        &header[OFF_WRAPPED..OFF_BODY_NONCE],
        &header[..KDF_AAD_LEN],
    )?;
    let mut dek = Zeroizing::new([0u8; KEY_LEN]);
    if plaintext.len() != KEY_LEN {
        bail!("wrapped data key has the wrong length");
    }
    dek.copy_from_slice(&plaintext);
    Ok(Opened { dek, kdf })
}

pub fn decrypt(passphrase: &SecretString, file: &[u8]) -> Result<(Zeroizing<Vec<u8>>, KdfParams)> {
    let (header, body, kdf) = parse(file)?;
    let opened = unwrap_dek(passphrase, header, kdf)?;
    let body_nonce = &header[OFF_BODY_NONCE..HEADER_LEN];
    let plaintext = unseal(&*opened.dek, body_nonce, body, &body_aad(body_nonce))?;
    Ok((plaintext, opened.kdf))
}

/// Rotate the File Passphrase by rewrapping the data key. The body ciphertext
/// is copied through untouched.
pub fn rekey(
    old: &SecretString,
    new: &SecretString,
    file: &[u8],
    kdf: KdfParams,
) -> Result<Vec<u8>> {
    let (header, body, existing_kdf) = parse(file)?;
    let opened = unwrap_dek(old, header, existing_kdf)?;
    let body_nonce = &header[OFF_BODY_NONCE..HEADER_LEN];

    let mut rewrapped = wrap(new, &*opened.dek, body_nonce, kdf)?;
    rewrapped.extend_from_slice(body);
    Ok(rewrapped)
}
