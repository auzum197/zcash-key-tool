//! Properties the Wallet File container must hold.

use secrecy::SecretString;
use zeroize::Zeroizing;
use zkeytool::envelope::{HEADER_LEN, KdfParams, decrypt, encrypt, rekey};
use zkeytool::network::Network;
use zkeytool::wallet::{RootSecret, Wallet};

fn passphrase(text: &str) -> SecretString {
    SecretString::from(text.to_owned())
}

const PLAINTEXT: &[u8] = b"a Root Secret lives here";

#[test]
fn roundtrips() {
    let file = encrypt(&passphrase("correct horse"), PLAINTEXT, KdfParams::FAST).expect("encrypt");
    let (recovered, kdf) = decrypt(&passphrase("correct horse"), &file).expect("decrypt");

    assert_eq!(&*recovered, PLAINTEXT);
    assert_eq!(kdf, KdfParams::FAST);
}

#[test]
fn the_wrong_passphrase_fails() {
    let file = encrypt(&passphrase("correct horse"), PLAINTEXT, KdfParams::FAST).expect("encrypt");

    let error = decrypt(&passphrase("correct hors"), &file).expect_err("must not open");
    assert!(error.to_string().contains("could not decrypt"), "{error}");
}

/// Cheap enough to run once per byte of the file. Real wallets never see it.
const FLIMSY: KdfParams = KdfParams {
    m_kib: 8,
    t: 1,
    p: 1,
};

#[test]
fn every_single_byte_is_authenticated() {
    let file = encrypt(&passphrase("correct horse"), PLAINTEXT, FLIMSY).expect("encrypt");

    for at in 0..file.len() {
        let mut damaged = file.clone();
        damaged[at] ^= 1;
        assert!(
            decrypt(&passphrase("correct horse"), &damaged).is_err(),
            "flipping a bit at offset {at} went undetected"
        );
    }
}

#[test]
fn truncation_is_detected() {
    let file = encrypt(&passphrase("correct horse"), PLAINTEXT, KdfParams::FAST).expect("encrypt");

    for len in [0, 1, HEADER_LEN - 1, HEADER_LEN, file.len() - 1] {
        assert!(
            decrypt(&passphrase("correct horse"), &file[..len]).is_err(),
            "a {len}-byte file was accepted"
        );
    }
}

#[test]
fn lowering_the_kdf_cost_in_place_breaks_authentication() {
    let file = encrypt(&passphrase("correct horse"), PLAINTEXT, KdfParams::FAST).expect("encrypt");

    let mut downgraded = file.clone();
    downgraded[8..12].copy_from_slice(&FLIMSY.m_kib.to_le_bytes());

    assert!(decrypt(&passphrase("correct horse"), &downgraded).is_err());
}

#[test]
fn rekey_keeps_the_body_and_swaps_the_passphrase() {
    let file = encrypt(&passphrase("old"), PLAINTEXT, KdfParams::FAST).expect("encrypt");
    let rotated = rekey(
        &passphrase("old"),
        &passphrase("new"),
        &file,
        KdfParams::FAST,
    )
    .expect("rekey");

    assert_eq!(
        &file[HEADER_LEN..],
        &rotated[HEADER_LEN..],
        "the body was re-encrypted when it should have been copied"
    );
    assert!(decrypt(&passphrase("old"), &rotated).is_err());

    let (recovered, _) = decrypt(&passphrase("new"), &rotated).expect("opens under the new one");
    assert_eq!(&*recovered, PLAINTEXT);
}

/// A hostile file names its own Argon2id cost. Refusal must come from the
/// bounds check in `parse`, before any memory is committed, which the error
/// text proves: only `KdfParams::check` speaks of what the file "asks for".
#[test]
fn a_hostile_kdf_cost_is_refused_by_the_bounds_check() {
    let file = encrypt(&passphrase("correct horse"), PLAINTEXT, FLIMSY).expect("encrypt");

    let cases: [(usize, u32, &str); 4] = [
        (8, u32::MAX, "Argon2id memory"), // m_kib: ~4 TiB
        (8, 7, "Argon2id memory"),        // m_kib below the floor
        (12, 0, "Argon2id passes"),       // t
        (16, 65, "lanes"),                // p
    ];
    for (at, value, fragment) in cases {
        let mut hostile = file.clone();
        hostile[at..at + 4].copy_from_slice(&value.to_le_bytes());
        let error =
            decrypt(&passphrase("correct horse"), &hostile).expect_err("hostile cost accepted");
        assert!(error.to_string().contains(fragment), "{error}");
    }
}

#[test]
fn parse_names_the_specific_header_problem() {
    let file = encrypt(&passphrase("correct horse"), PLAINTEXT, KdfParams::FAST).expect("encrypt");

    let cases: [(usize, u8, &str); 3] = [
        (0, b'X', "bad magic bytes"),
        (6, 2, "unsupported Wallet File version 2"),
        (7, 3, "unsupported key derivation function id 3"),
    ];
    for (at, value, fragment) in cases {
        let mut damaged = file.clone();
        damaged[at] = value;
        let error = decrypt(&passphrase("correct horse"), &damaged).expect_err("parsed anyway");
        assert!(error.to_string().contains(fragment), "{error}");
    }
}

/// Two files under the same passphrase must not be mixable, even though the
/// body AAD deliberately leaves the salt and wrapped key unbound.
#[test]
fn a_header_spliced_onto_another_body_fails() {
    let a = encrypt(&passphrase("correct horse"), b"body a", FLIMSY).expect("encrypt");
    let b = encrypt(&passphrase("correct horse"), b"body b", FLIMSY).expect("encrypt");
    let body_nonce_at = HEADER_LEN - 24;

    let mut whole_header = a[..HEADER_LEN].to_vec();
    whole_header.extend_from_slice(&b[HEADER_LEN..]);

    let mut nonce_too = a[..body_nonce_at].to_vec();
    nonce_too.extend_from_slice(&b[body_nonce_at..]);

    for spliced in [whole_header, nonce_too] {
        assert!(
            decrypt(&passphrase("correct horse"), &spliced).is_err(),
            "a spliced file was accepted"
        );
    }
}

#[test]
fn rekey_records_the_new_cost() {
    let file = encrypt(&passphrase("old"), PLAINTEXT, KdfParams::FAST).expect("encrypt");
    let rotated = rekey(&passphrase("old"), &passphrase("new"), &file, FLIMSY).expect("rekey");

    let (_, kdf) = decrypt(&passphrase("new"), &rotated).expect("opens");
    assert_eq!(kdf, FLIMSY);
}

/// The CLI refuses to *set* an empty File Passphrase. The envelope stays
/// permissive so a file that somehow has one can still be opened.
#[test]
fn the_envelope_itself_accepts_an_empty_passphrase() {
    let file = encrypt(&passphrase(""), PLAINTEXT, FLIMSY).expect("encrypt");
    let (recovered, _) = decrypt(&passphrase(""), &file).expect("decrypt");
    assert_eq!(&*recovered, PLAINTEXT);
}

#[test]
fn rekey_rejects_the_wrong_current_passphrase() {
    let file = encrypt(&passphrase("old"), PLAINTEXT, KdfParams::FAST).expect("encrypt");
    assert!(
        rekey(
            &passphrase("nope"),
            &passphrase("new"),
            &file,
            KdfParams::FAST
        )
        .is_err()
    );
}

#[test]
fn every_root_secret_variant_survives_the_body_codec() {
    let variants = [
        RootSecret::Mnemonic {
            entropy: Zeroizing::new(vec![7u8; 32]),
            seed_passphrase: SecretString::from("hunter2".to_owned()),
        },
        RootSecret::Seed(Zeroizing::new(vec![3u8; 64])),
        RootSecret::Ufvk("uview1notreallyakey".to_owned()),
        RootSecret::Uivk("uivk1notreallyakey".to_owned()),
        RootSecret::SaplingExtendedSpendingKey(Zeroizing::new(vec![9u8; 169])),
    ];

    for root in variants {
        let kind = root.kind();
        let wallet = Wallet {
            network: Network::Test,
            root,
        };
        let body = wallet.encode().expect("body encodes");
        let decoded = Wallet::decode(&body).expect("body decodes");

        assert_eq!(decoded.network, Network::Test, "{kind}");
        assert_eq!(decoded.root.kind(), kind);
        assert_eq!(
            decoded.encode().expect("re-encodes"),
            body,
            "{kind} did not round-trip"
        );
    }
}

#[test]
fn body_decode_rejects_malformed_input() {
    let valid = Wallet {
        network: Network::Test,
        root: RootSecret::Seed(Zeroizing::new(vec![3u8; 32])),
    }
    .encode()
    .expect("encodes");
    let mut trailing = valid.to_vec();
    trailing.push(0);

    let mut short_entropy = vec![1, 0, 1, 32]; // announces 32 bytes of entropy
    short_entropy.extend_from_slice(&[0u8; 10]); // delivers 10

    let mut bad_entropy = vec![1, 0, 1, 17]; // 17 bytes is no BIP-39 size
    bad_entropy.extend_from_slice(&[0u8; 17]);
    bad_entropy.extend_from_slice(&0u16.to_le_bytes());

    let mut short_seed = vec![1, 0, 2, 16]; // a 16-byte seed is below the floor
    short_seed.extend_from_slice(&[0u8; 16]);

    let cases: [(Vec<u8>, &str); 8] = [
        (trailing, "trailing data"),
        (vec![], "truncated"),
        (vec![2], "unsupported Wallet File body version"),
        (vec![1, 7], "unknown network tag"),
        (vec![1, 0, 9], "unknown Root Secret kind"),
        (short_entropy, "truncated"),
        (bad_entropy, "not a BIP-39 length"),
        (short_seed, "between 32 and 64"),
    ];
    for (body, fragment) in cases {
        let Err(error) = Wallet::decode(&body) else {
            panic!("malformed body decoded: {body:?}");
        };
        assert!(error.to_string().contains(fragment), "{error}");
    }

    let utf8 = vec![1, 0, 3, 2, 0, 0xff, 0xfe]; // a UFVK that is not UTF-8
    let Err(error) = Wallet::decode(&utf8) else {
        panic!("bad UTF-8 decoded");
    };
    assert!(error.to_string().contains("not valid UTF-8"), "{error}");
}

#[test]
fn encode_refuses_material_the_format_cannot_hold() {
    let cases = [
        (
            RootSecret::Seed(Zeroizing::new(vec![7u8; 300])),
            "between 32 and 64",
        ),
        (
            RootSecret::Mnemonic {
                entropy: Zeroizing::new(vec![7u8; 33]),
                seed_passphrase: SecretString::from(String::new()),
            },
            "not a BIP-39 length",
        ),
        (
            RootSecret::SaplingExtendedSpendingKey(Zeroizing::new(vec![9u8; 168])),
            "169 bytes",
        ),
    ];
    for (root, fragment) in cases {
        let wallet = Wallet {
            network: Network::Main,
            root,
        };
        let Err(error) = wallet.encode() else {
            panic!("oversized {} encoded", wallet.root.kind());
        };
        assert!(error.to_string().contains(fragment), "{error}");
    }
}

#[test]
fn a_seed_passphrase_changes_the_seed() {
    let without = RootSecret::Mnemonic {
        entropy: Zeroizing::new(vec![0u8; 32]),
        seed_passphrase: SecretString::from(String::new()),
    };
    let with = RootSecret::Mnemonic {
        entropy: Zeroizing::new(vec![0u8; 32]),
        seed_passphrase: SecretString::from("25th word".to_owned()),
    };

    assert_ne!(without.seed().expect("seed"), with.seed().expect("seed"));
    assert_eq!(without.mnemonic_phrase(), with.mnemonic_phrase());
}
