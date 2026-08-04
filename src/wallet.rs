//! The Root Secret and the plaintext body of a Wallet File.

use anyhow::{Result, anyhow, bail};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use crate::network::Network;

const BODY_VERSION: u8 = 1;

const KIND_MNEMONIC: u8 = 1;
const KIND_SEED: u8 = 2;
const KIND_UFVK: u8 = 3;
const KIND_UIVK: u8 = 4;
const KIND_SAPLING_EXTSK: u8 = 5;

pub const SAPLING_EXTSK_LEN: usize = 169;

fn check_entropy_len(n: usize) -> Result<()> {
    if !matches!(n, 16 | 20 | 24 | 28 | 32) {
        bail!("Mnemonic entropy of {n} bytes is not a BIP-39 length");
    }
    Ok(())
}

pub fn check_seed_len(n: usize) -> Result<()> {
    if !(32..=64).contains(&n) {
        bail!("a seed must be between 32 and 64 bytes, got {n}");
    }
    Ok(())
}

fn check_string_len(n: usize) -> Result<()> {
    if n > u16::MAX as usize {
        bail!("{n} bytes is too long for a Wallet File body string");
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Capability {
    Spend,
    FullView,
    IncomingView,
}

impl Capability {
    pub fn label(self) -> &'static str {
        match self {
            Self::Spend => "spend",
            Self::FullView => "full-view",
            Self::IncomingView => "incoming-view",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PoolCoverage {
    pub orchard: bool,
    pub sapling: bool,
    pub transparent: bool,
}

impl PoolCoverage {
    pub const SAPLING_ONLY: Self = Self {
        orchard: false,
        sapling: true,
        transparent: false,
    };

    pub fn labels(&self) -> Vec<&'static str> {
        let mut pools = Vec::new();
        if self.orchard {
            pools.push("orchard");
        }
        if self.sapling {
            pools.push("sapling");
        }
        if self.transparent {
            pools.push("transparent");
        }
        pools
    }
}

pub enum RootSecret {
    Mnemonic {
        entropy: Zeroizing<Vec<u8>>,
        seed_passphrase: SecretString,
    },
    Seed(Zeroizing<Vec<u8>>),
    Ufvk(String),
    Uivk(String),
    SaplingExtendedSpendingKey(Zeroizing<Vec<u8>>),
}

impl RootSecret {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Mnemonic { .. } => "mnemonic",
            Self::Seed(_) => "seed",
            Self::Ufvk(_) => "ufvk",
            Self::Uivk(_) => "uivk",
            Self::SaplingExtendedSpendingKey(_) => "sapling-extended-spending-key",
        }
    }

    pub fn capability(&self) -> Capability {
        match self {
            Self::Mnemonic { .. } | Self::Seed(_) | Self::SaplingExtendedSpendingKey(_) => {
                Capability::Spend
            }
            Self::Ufvk(_) => Capability::FullView,
            Self::Uivk(_) => Capability::IncomingView,
        }
    }

    /// Whether the Network is fixed by the Root Secret itself rather than by
    /// the file's stored default. Imported encodings carry their network in
    /// their human-readable prefix, so overriding it would be a lie.
    pub fn network_is_intrinsic(&self) -> bool {
        matches!(
            self,
            Self::Ufvk(_) | Self::Uivk(_) | Self::SaplingExtendedSpendingKey(_)
        )
    }

    /// The 64-byte BIP-39 seed, for the variants that have one.
    pub fn seed(&self) -> Option<Zeroizing<Vec<u8>>> {
        match self {
            Self::Mnemonic {
                entropy,
                seed_passphrase,
            } => bip0039::Mnemonic::<bip0039::English>::from_entropy(entropy.to_vec())
                .ok()
                .map(|m| Zeroizing::new(m.to_seed(seed_passphrase.expose_secret()).to_vec())),
            Self::Seed(bytes) => Some(bytes.clone()),
            _ => None,
        }
    }

    pub fn mnemonic_phrase(&self) -> Option<Zeroizing<String>> {
        match self {
            Self::Mnemonic { entropy, .. } => {
                bip0039::Mnemonic::<bip0039::English>::from_entropy(entropy.to_vec())
                    .ok()
                    .map(|m| Zeroizing::new(m.into_phrase()))
            }
            _ => None,
        }
    }
}

pub struct Wallet {
    pub network: Network,
    pub root: RootSecret,
}

fn network_byte(network: Network) -> u8 {
    match network {
        Network::Main => 0,
        Network::Test => 1,
        Network::Regtest => 2,
    }
}

fn network_from_byte(byte: u8) -> Result<Network> {
    match byte {
        0 => Ok(Network::Main),
        1 => Ok(Network::Test),
        2 => Ok(Network::Regtest),
        other => bail!("unknown network tag {other} in Wallet File body"),
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .at
            .checked_add(n)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| anyhow!("Wallet File body is truncated"))?;
        let slice = &self.bytes[self.at..end];
        self.at = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<usize> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]) as usize)
    }

    fn short_string(&mut self) -> Result<String> {
        let len = self.u16()?;
        let bytes = self.take(len)?;
        String::from_utf8(bytes.to_vec())
            .map_err(|_| anyhow!("Wallet File body is not valid UTF-8"))
    }
}

impl Wallet {
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut body = Zeroizing::new(Vec::new());
        body.push(BODY_VERSION);
        body.push(network_byte(self.network));

        match &self.root {
            RootSecret::Mnemonic {
                entropy,
                seed_passphrase,
            } => {
                check_entropy_len(entropy.len())?;
                body.push(KIND_MNEMONIC);
                body.push(entropy.len() as u8);
                body.extend_from_slice(entropy);
                let passphrase = seed_passphrase.expose_secret().as_bytes();
                check_string_len(passphrase.len())?;
                body.extend_from_slice(&(passphrase.len() as u16).to_le_bytes());
                body.extend_from_slice(passphrase);
            }
            RootSecret::Seed(seed) => {
                check_seed_len(seed.len())?;
                body.push(KIND_SEED);
                body.push(seed.len() as u8);
                body.extend_from_slice(seed);
            }
            RootSecret::Ufvk(encoding) => {
                check_string_len(encoding.len())?;
                body.push(KIND_UFVK);
                body.extend_from_slice(&(encoding.len() as u16).to_le_bytes());
                body.extend_from_slice(encoding.as_bytes());
            }
            RootSecret::Uivk(encoding) => {
                check_string_len(encoding.len())?;
                body.push(KIND_UIVK);
                body.extend_from_slice(&(encoding.len() as u16).to_le_bytes());
                body.extend_from_slice(encoding.as_bytes());
            }
            RootSecret::SaplingExtendedSpendingKey(bytes) => {
                if bytes.len() != SAPLING_EXTSK_LEN {
                    bail!(
                        "a Sapling extended spending key is {SAPLING_EXTSK_LEN} bytes, got {}",
                        bytes.len()
                    );
                }
                body.push(KIND_SAPLING_EXTSK);
                body.extend_from_slice(bytes);
            }
        }
        Ok(body)
    }

    pub fn decode(body: &[u8]) -> Result<Self> {
        let mut cursor = Cursor { bytes: body, at: 0 };
        let version = cursor.u8()?;
        if version != BODY_VERSION {
            bail!("unsupported Wallet File body version {version}");
        }
        let network = network_from_byte(cursor.u8()?)?;

        let root = match cursor.u8()? {
            KIND_MNEMONIC => {
                let entropy_len = cursor.u8()? as usize;
                check_entropy_len(entropy_len)?;
                let entropy = Zeroizing::new(cursor.take(entropy_len)?.to_vec());
                let seed_passphrase = SecretString::from(cursor.short_string()?);
                RootSecret::Mnemonic {
                    entropy,
                    seed_passphrase,
                }
            }
            KIND_SEED => {
                let len = cursor.u8()? as usize;
                check_seed_len(len)?;
                RootSecret::Seed(Zeroizing::new(cursor.take(len)?.to_vec()))
            }
            KIND_UFVK => RootSecret::Ufvk(cursor.short_string()?),
            KIND_UIVK => RootSecret::Uivk(cursor.short_string()?),
            KIND_SAPLING_EXTSK => RootSecret::SaplingExtendedSpendingKey(Zeroizing::new(
                cursor.take(SAPLING_EXTSK_LEN)?.to_vec(),
            )),
            other => bail!("unknown Root Secret kind {other}"),
        };

        if cursor.at != body.len() {
            bail!(
                "Wallet File body has {} bytes of trailing data",
                body.len() - cursor.at
            );
        }
        Ok(Self { network, root })
    }
}
