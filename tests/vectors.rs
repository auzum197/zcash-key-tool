//! Derivation checked against published test vectors.
//!
//! The vendored JSON under `tests/vectors/` comes from the Trezor BIP-39 suite
//! and from zcash/zcash-test-vectors, the generator behind the ZIP appendices.
//! Checking against `zcash_keys`' own vectors would only prove that the crate
//! agrees with itself.

use derivator::network::Network;
use derivator::view::{Pool, ViewParams, derive};
use derivator::wallet::{RootSecret, Wallet};
use secrecy::SecretString;
use serde_json::Value;
use zcash_keys::keys::{UnifiedFullViewingKey, UnifiedSpendingKey};
use zcash_protocol::consensus::NetworkConstants;
use zeroize::Zeroizing;
use zip32::{AccountId, ChildIndex, DiversifierIndex, Scope};

fn load(name: &str) -> Vec<Vec<Value>> {
    let raw = std::fs::read_to_string(format!(
        "{}/tests/vectors/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("vector file is vendored in the repo");
    serde_json::from_str::<Vec<Vec<Value>>>(&raw).expect("vector file is a JSON array of rows")
}

/// Skip the provenance comment and the field-name row.
fn rows(name: &str) -> Vec<Vec<Value>> {
    load(name).into_iter().skip(2).collect()
}

fn hex_at(row: &[Value], at: usize) -> Option<Vec<u8>> {
    row[at]
        .as_str()
        .map(|s| hex::decode(s).expect("vector hex"))
}

fn seed_wallet(seed: &[u8]) -> Wallet {
    Wallet {
        network: Network::Main,
        root: RootSecret::Seed(Zeroizing::new(seed.to_vec())),
    }
}

fn params(account: u32, j: u128, receivers: Option<Vec<Pool>>) -> ViewParams {
    ViewParams {
        network: Network::Main,
        account,
        diversifier_index: j,
        index_given: true,
        scope: Scope::External,
        receivers,
        path: None,
    }
}

#[test]
fn bip39_trezor_vectors() {
    let vectors: Vec<Vec<String>> = serde_json::from_str(
        &std::fs::read_to_string(format!(
            "{}/tests/vectors/bip39_trezor_english.json",
            env!("CARGO_MANIFEST_DIR")
        ))
        .expect("vendored"),
    )
    .expect("array of [entropy, mnemonic, seed, xprv]");

    assert!(!vectors.is_empty());
    for vector in &vectors {
        let entropy = hex::decode(&vector[0]).expect("vector hex");
        let root = RootSecret::Mnemonic {
            entropy: Zeroizing::new(entropy),
            // Every Trezor vector uses this Seed Passphrase.
            seed_passphrase: SecretString::from("TREZOR".to_owned()),
        };

        assert_eq!(
            root.mnemonic_phrase().expect("mnemonic root").as_str(),
            vector[1],
            "phrase for entropy {}",
            vector[0]
        );
        assert_eq!(
            hex::encode(&*root.seed().expect("mnemonic root")),
            vector[2],
            "seed for entropy {}",
            vector[0]
        );
    }
}

/// ZIP-316 unified addresses, end to end from a seed.
#[test]
fn zip316_unified_addresses() {
    let mut checked = 0;

    for row in rows("unified_address.json") {
        // Rows carrying a P2SH receiver or an unknown typecode describe
        // addresses no key derivation can produce.
        if !row[1].is_null() || !row[4].is_null() {
            continue;
        }

        let mut receivers = Vec::new();
        if !row[0].is_null() {
            receivers.push(Pool::P2pkh);
        }
        if !row[2].is_null() {
            receivers.push(Pool::Sapling);
        }
        if !row[3].is_null() {
            receivers.push(Pool::Orchard);
        }
        if receivers.is_empty() {
            continue;
        }

        let seed = hex_at(&row, 7).expect("root_seed");
        let account = row[8].as_u64().expect("account") as u32;
        let j = row[9].as_u64().expect("diversifier_index") as u128;
        let expected = row[6].as_str().expect("unified_addr");

        let wallet = seed_wallet(&seed);
        let view = derive(&wallet, &params(account, j, Some(receivers)), false)
            .unwrap_or_else(|e| panic!("account {account}, index {j}: {e}"));

        assert_eq!(
            view.unified_address.as_deref(),
            Some(expected),
            "unified address for account {account}, diversifier index {j}"
        );
        checked += 1;
    }

    assert!(checked >= 40, "only {checked} unified address vectors ran");
}

/// The published UFVK vectors all carry an unknown FVK item, so compare the
/// individual pool components rather than the assembled encoding.
#[test]
fn zip316_ufvk_components() {
    let mut checked = 0;

    for row in rows("unified_full_viewing_keys.json") {
        let seed = hex_at(&row, 6).expect("root_seed");
        let account = row[7].as_u64().expect("account") as u32;
        let usk = UnifiedSpendingKey::from_seed(
            &Network::Main,
            &seed,
            AccountId::try_from(account).expect("account in range"),
        )
        .expect("derivable account");
        let ufvk = usk.to_unified_full_viewing_key();

        if let Some(expected) = hex_at(&row, 0) {
            let derived = ufvk
                .transparent()
                .expect("transparent component")
                .serialize();
            assert_eq!(derived, expected, "transparent key for account {account}");
            checked += 1;
        }
        if let Some(expected) = hex_at(&row, 1) {
            let derived = ufvk.sapling().expect("sapling component").to_bytes();
            assert_eq!(
                derived.to_vec(),
                expected,
                "sapling FVK for account {account}"
            );
            checked += 1;
        }
        if let Some(expected) = hex_at(&row, 2) {
            let derived = ufvk.orchard().expect("orchard component").to_bytes();
            assert_eq!(
                derived.to_vec(),
                expected,
                "orchard FVK for account {account}"
            );
            checked += 1;
        }
    }

    assert!(checked >= 20, "only {checked} UFVK components ran");
}

/// ZIP-32 hardened Sapling derivation, exercising the `--path` surface.
/// The generator seeds these with `bytes(range(32))`.
#[test]
fn zip32_hardened_sapling_path() {
    let seed: Vec<u8> = (0u8..32).collect();
    let paths: [Vec<ChildIndex>; 4] = [
        vec![],
        vec![ChildIndex::hardened(1)],
        vec![ChildIndex::hardened(1), ChildIndex::hardened(2)],
        vec![
            ChildIndex::hardened(1),
            ChildIndex::hardened(2),
            ChildIndex::hardened(3),
        ],
    ];

    let vectors = rows("sapling_zip32_hard.json");
    assert_eq!(vectors.len(), paths.len());

    let master = zcash_keys::keys::sapling::ExtendedSpendingKey::master(&seed);
    for (path, row) in paths.iter().zip(vectors) {
        let expected = hex_at(&row, 8).expect("xsk");
        let derived = zcash_keys::keys::sapling::ExtendedSpendingKey::from_path(&master, path);
        assert_eq!(derived.to_bytes().to_vec(), expected, "xsk at {path:?}");
    }
}

/// A literal path of the standard shape must agree with the same account
/// selected by `--account`.
#[test]
fn path_and_account_agree() {
    let seed: Vec<u8> = (0u8..32).collect();
    let wallet = seed_wallet(&seed);

    let by_account = derive(&wallet, &params(7, 0, None), false).expect("account view");

    let mut by_path = params(0, 0, None);
    by_path.path = Some(derivator::view::parse_path("m/32'/133'/7'").expect("valid path"));
    let by_path = derive(&wallet, &by_path, false).expect("path view");

    assert_eq!(by_account.unified_address, by_path.unified_address);
    assert_eq!(by_account.ufvk, by_path.ufvk);
    assert_eq!(by_path.path.as_deref(), Some("m/32'/133'/7'"));
}

/// The same ZIP-32 vectors as above, but driven through derivator's own
/// `--path` surface: `derive_by_path`, `sapling_only`, and the `reveal`
/// encoding, with the vendored xsk bytes as the anchor.
#[test]
fn nonstandard_paths_flow_through_the_path_surface() {
    let seed: Vec<u8> = (0u8..32).collect();
    let wallet = seed_wallet(&seed);
    let raw_paths = ["m", "m/1'", "m/1'/2'", "m/1'/2'/3'"];

    let vectors = rows("sapling_zip32_hard.json");
    assert_eq!(vectors.len(), raw_paths.len());

    for (raw, row) in raw_paths.iter().zip(vectors) {
        let expected = hex_at(&row, 8).expect("xsk");

        let mut with_path = params(0, 0, None);
        with_path.index_given = false;
        with_path.path = Some(derivator::view::parse_path(raw).expect("valid path"));
        let view = derive(&wallet, &with_path, true).expect("path view");

        let encoded = view
            .secrets
            .expect("revealed")
            .sapling_extended_spending_key
            .expect("a path derivation always reaches Sapling");
        let extsk = zcash_keys::encoding::decode_extended_spending_key(
            Network::Main.hrp_sapling_extended_spending_key(),
            &encoded,
        )
        .expect("own encoding decodes");

        assert_eq!(extsk.to_bytes().to_vec(), expected, "xsk via {raw}");
        assert!(
            view.notes.iter().any(|n| n.contains("never Orchard")),
            "the off-path warning is missing for {raw}"
        );
    }
}

#[test]
fn parse_path_rejects_what_zip32_cannot_hold() {
    let cases = [
        ("32'/133'/0'", "starts with 'm'"),
        ("m/2147483648'", "out of range"),
        ("m/x'", "not a derivation path element"),
    ];
    for (raw, fragment) in cases {
        let error = derivator::view::parse_path(raw).expect_err("parsed anyway");
        assert!(error.to_string().contains(fragment), "{raw}: {error}");
    }
}

#[test]
fn a_viewing_root_cannot_walk_a_path() {
    let seed: Vec<u8> = (0u8..32).collect();
    let usk = UnifiedSpendingKey::from_seed(
        &Network::Main,
        &seed,
        AccountId::try_from(0).expect("account"),
    )
    .expect("usk");
    let watch = Wallet {
        network: Network::Main,
        root: RootSecret::Ufvk(usk.to_unified_full_viewing_key().encode(&Network::Main)),
    };

    let mut with_path = params(0, 0, None);
    with_path.path = Some(derivator::view::parse_path("m/1'").expect("valid path"));
    let error = derive(&watch, &with_path, false).expect_err("a UFVK holds no seed");
    assert!(
        error.to_string().contains("needs a Mnemonic or a seed"),
        "{error}"
    );
}

/// A stored encoding that no longer decodes must name itself, not pretend the
/// passphrase was wrong.
#[test]
fn a_stored_key_that_does_not_decode_is_reported() {
    let cases = [
        (RootSecret::Ufvk("uview1garbage".to_owned()), "stored UFVK"),
        (RootSecret::Uivk("uivk1garbage".to_owned()), "stored UIVK"),
    ];
    for (root, fragment) in cases {
        let wallet = Wallet {
            network: Network::Main,
            root,
        };
        let error = derive(&wallet, &params(0, 0, None), false).expect_err("decoded garbage");
        assert!(error.to_string().contains(fragment), "{error}");
    }
}

#[test]
fn a_sapling_extended_spending_key_root_has_one_pool_and_two_scopes() {
    let seed: Vec<u8> = (0u8..32).collect();
    let master = zcash_keys::keys::sapling::ExtendedSpendingKey::master(&seed);
    let wallet = Wallet {
        network: Network::Main,
        root: RootSecret::SaplingExtendedSpendingKey(Zeroizing::new(master.to_bytes().to_vec())),
    };

    let asked_for_orchard = derive(
        &wallet,
        &params(0, 0, Some(vec![Pool::Orchard, Pool::Sapling])),
        false,
    )
    .expect("still derives");
    assert!(
        asked_for_orchard
            .notes
            .iter()
            .any(|n| n.contains("only the Sapling pool")),
        "the single-pool limitation goes unmentioned"
    );

    let mut internal = params(0, 0, None);
    internal.scope = Scope::Internal;
    let change = derive(&wallet, &internal, false).expect("change view");
    assert_eq!(change.address_receivers, ["sapling"]);
    assert_ne!(
        change.unified_address,
        derive(&wallet, &params(0, 0, None), false)
            .expect("external view")
            .unified_address
    );

    let dfvk = master.to_diversifiable_full_viewing_key();
    let gap = (0u128..)
        .find(|j| {
            dfvk.address(DiversifierIndex::try_from(*j).expect("in range"))
                .is_none()
        })
        .expect("some index has no Sapling address");
    let error = derive(&wallet, &params(0, gap, None), false).expect_err("pinned to a gap");
    assert!(
        error.to_string().contains("no valid Sapling address"),
        "{error}"
    );
}

/// Sapling change addresses live at one index. Asking for the internal scope
/// at any other index must say where they actually are.
#[test]
fn the_sapling_change_index_note_names_the_real_index() {
    let seed: Vec<u8> = (0u8..32).collect();
    let usk = UnifiedSpendingKey::from_seed(
        &Network::Main,
        &seed,
        AccountId::try_from(0).expect("account"),
    )
    .expect("usk");
    let (at, _) = usk
        .to_unified_full_viewing_key()
        .sapling()
        .expect("sapling component")
        .change_address();
    let elsewhere = u128::from(at) + 1;

    let wallet = seed_wallet(&seed);
    let mut internal = params(0, elsewhere, None);
    internal.scope = Scope::Internal;
    let view = derive(&wallet, &internal, false).expect("internal view");
    assert!(
        view.notes
            .iter()
            .any(|n| n.contains("default diversifier index")),
        "the change-index caveat goes unmentioned: {:?}",
        view.notes
    );

    // Above the BIP-32 limit the change address simply drops its transparent
    // receiver, like the external one does.
    let mut high = params(0, 1 << 31, None);
    high.scope = Scope::Internal;
    let dropped = derive(&wallet, &high, false).expect("internal view");
    assert!(!dropped.address_receivers.contains(&"p2pkh"));
}

#[test]
fn internal_scope_yields_a_different_complete_address() {
    let seed: Vec<u8> = (0u8..32).collect();
    let wallet = seed_wallet(&seed);

    let mut internal = params(0, 0, None);
    internal.scope = Scope::Internal;
    let change = derive(&wallet, &internal, false).expect("internal view");
    let external = derive(&wallet, &params(0, 0, None), false).expect("external view");

    let address = change.unified_address.expect("change address");
    assert_ne!(Some(&address), external.unified_address.as_ref());
    assert_eq!(change.scope, "internal");
    for pool in ["orchard", "sapling", "p2pkh"] {
        assert!(
            change.address_receivers.contains(&pool),
            "change address lacks {pool}"
        );
    }
}

#[test]
fn a_uivk_root_matches_its_ufvk_and_stays_external_only() {
    let seed: Vec<u8> = (0u8..32).collect();
    let usk = UnifiedSpendingKey::from_seed(
        &Network::Main,
        &seed,
        AccountId::try_from(0).expect("account"),
    )
    .expect("usk");
    let uivk = usk
        .to_unified_full_viewing_key()
        .to_unified_incoming_viewing_key()
        .encode(&Network::Main);
    let watch = Wallet {
        network: Network::Main,
        root: RootSecret::Uivk(uivk),
    };

    let mut searched = params(0, 0, None);
    searched.index_given = false;
    let from_uivk = derive(&watch, &searched, false).expect("uivk view");
    let from_seed = derive(&seed_wallet(&seed), &searched, false).expect("seed view");

    assert_eq!(from_uivk.unified_address, from_seed.unified_address);
    assert_eq!(from_uivk.capability, "incoming-view");
    assert_eq!(
        from_uivk.pool_coverage,
        ["orchard", "sapling", "transparent"]
    );
    assert_eq!(
        from_uivk.account, None,
        "an imported key cannot know its account"
    );
    assert!(from_uivk.ufvk.is_none());

    let mut internal = searched.clone();
    internal.scope = Scope::Internal;
    let refused = derive(&watch, &internal, false).expect("still a view");
    assert!(refused.unified_address.is_none());
    assert!(
        refused.notes.iter().any(|n| n.contains("full viewing key")),
        "the UIVK limitation goes unmentioned"
    );
}

#[test]
fn a_uivk_serves_a_pinned_index_too() {
    let seed: Vec<u8> = (0u8..32).collect();
    let usk = UnifiedSpendingKey::from_seed(
        &Network::Main,
        &seed,
        AccountId::try_from(0).expect("account"),
    )
    .expect("usk");
    let watch = Wallet {
        network: Network::Main,
        root: RootSecret::Uivk(
            usk.to_unified_full_viewing_key()
                .to_unified_incoming_viewing_key()
                .encode(&Network::Main),
        ),
    };

    let mut searched = params(0, 0, None);
    searched.index_given = false;
    let found = derive(&watch, &searched, false).expect("search view");
    let landed: u128 = found
        .diversifier_index
        .as_deref()
        .expect("index")
        .parse()
        .expect("numeric");

    let pinned = derive(&watch, &params(0, landed, None), false).expect("pinned view");
    assert_eq!(pinned.unified_address, found.unified_address);
}

#[test]
fn an_explicit_receiver_list_is_honoured_exactly() {
    let seed: Vec<u8> = (0u8..32).collect();
    let wallet = seed_wallet(&seed);

    let orchard_only = derive(&wallet, &params(0, 0, Some(vec![Pool::Orchard])), false)
        .expect("orchard-only view");
    assert_eq!(orchard_only.address_receivers, ["orchard"]);

    let error = derive(&wallet, &params(0, 0, Some(vec![Pool::P2pkh])), false)
        .expect_err("ZIP-316 forbids a transparent-only Unified Address");
    assert!(error.to_string().contains("shielded receiver"), "{error}");
}

/// The behaviour split: a searched index walks and says so, a pinned index
/// shows what is valid there and notes the rest.
#[test]
fn the_diversifier_search_and_the_pinned_index_both_explain_themselves() {
    let seed: Vec<u8> = (0u8..32).collect();
    let usk = UnifiedSpendingKey::from_seed(
        &Network::Main,
        &seed,
        AccountId::try_from(0).expect("account"),
    )
    .expect("usk");
    let ufvk = usk.to_unified_full_viewing_key();
    let dfvk = ufvk.sapling().expect("sapling component");
    let gap = (0u128..)
        .find(|j| {
            dfvk.address(DiversifierIndex::try_from(*j).expect("in range"))
                .is_none()
        })
        .expect("roughly half of all indices have no Sapling address");

    let wallet = seed_wallet(&seed);
    let mut searched = params(0, gap, None);
    searched.index_given = false;
    let walked = derive(&wallet, &searched, false).expect("search view");
    assert_ne!(walked.diversifier_index, Some(gap.to_string()));
    assert!(
        walked
            .notes
            .iter()
            .any(|n| n.contains("has no valid sapling address")),
        "the search went unmentioned: {:?}",
        walked.notes
    );

    let pinned = derive(&wallet, &params(0, gap, None), false).expect("pinned view");
    assert_eq!(pinned.diversifier_index, Some(gap.to_string()));
    assert!(!pinned.address_receivers.contains(&"sapling"));
    assert!(
        pinned
            .notes
            .iter()
            .any(|n| n.contains("sapling receiver omitted")),
        "the omission went unmentioned: {:?}",
        pinned.notes
    );
}

#[test]
fn above_the_bip32_limit_the_transparent_receiver_is_dropped_with_a_note() {
    let seed: Vec<u8> = (0u8..32).collect();
    let wallet = seed_wallet(&seed);

    let view = derive(&wallet, &params(0, 1 << 31, None), false).expect("view");
    assert!(!view.address_receivers.contains(&"p2pkh"));
    assert!(
        view.notes
            .iter()
            .any(|n| n.contains("transparent receiver omitted")),
        "the omission went unmentioned: {:?}",
        view.notes
    );
}

#[test]
fn testnet_paths_use_coin_type_1() {
    let seed: Vec<u8> = (0u8..32).collect();
    let wallet = Wallet {
        network: Network::Test,
        root: RootSecret::Seed(Zeroizing::new(seed)),
    };
    let testnet = |account, path: Option<&str>| {
        let mut p = params(account, 0, None);
        p.network = Network::Test;
        p.path = path.map(|raw| derivator::view::parse_path(raw).expect("valid path"));
        p
    };

    let by_account = derive(&wallet, &testnet(3, None), false).expect("account view");
    let by_path = derive(&wallet, &testnet(0, Some("m/32'/1'/3'")), false).expect("path view");
    assert_eq!(by_account.unified_address, by_path.unified_address);

    // The mainnet coin type is not the standard path on testnet.
    let foreign =
        derive(&wallet, &testnet(0, Some("m/32'/133'/3'")), false).expect("still derives");
    assert_ne!(foreign.unified_address, by_account.unified_address);
    assert!(foreign.notes.iter().any(|n| n.contains("never Orchard")));
}

/// Testnet and Regtest share coin type 1, so one Root Secret yields the same key
/// bytes on both and only the prefix table separates them. Nothing upstream
/// pins a regtest encoding, so the anchor is the vector-pinned key itself:
/// encode it twice, then decode the regtest string back to those bytes.
#[test]
fn regtest_and_testnet_encode_one_key_under_different_prefixes() {
    let mut checked = 0;

    for row in rows("unified_full_viewing_keys.json") {
        let seed = hex_at(&row, 6).expect("root_seed");
        let account = row[7].as_u64().expect("account") as u32;
        let ufvk = UnifiedSpendingKey::from_seed(
            &Network::Main,
            &seed,
            AccountId::try_from(account).expect("account in range"),
        )
        .expect("derivable account")
        .to_unified_full_viewing_key();

        let on_test = ufvk.encode(&Network::Test);
        let on_regtest = ufvk.encode(&Network::Regtest);
        assert_ne!(on_test, on_regtest, "UFVK for account {account}");
        assert!(
            on_test.starts_with(Network::Test.hrp_unified_fvk()),
            "testnet UFVK carries the wrong prefix: {on_test}"
        );
        assert!(
            on_regtest.starts_with(Network::Regtest.hrp_unified_fvk()),
            "regtest UFVK carries the wrong prefix: {on_regtest}"
        );

        let decoded = UnifiedFullViewingKey::decode(&Network::Regtest, &on_regtest)
            .expect("a regtest encoding decodes on regtest");
        if let Some(expected) = hex_at(&row, 0) {
            let derived = decoded
                .transparent()
                .expect("transparent component")
                .serialize();
            assert_eq!(derived, expected, "transparent key for account {account}");
            checked += 1;
        }
        if let Some(expected) = hex_at(&row, 1) {
            let derived = decoded.sapling().expect("sapling component").to_bytes();
            assert_eq!(
                derived.to_vec(),
                expected,
                "sapling FVK for account {account}"
            );
            checked += 1;
        }
        if let Some(expected) = hex_at(&row, 2) {
            let derived = decoded.orchard().expect("orchard component").to_bytes();
            assert_eq!(
                derived.to_vec(),
                expected,
                "orchard FVK for account {account}"
            );
            checked += 1;
        }
    }

    assert!(checked >= 20, "only {checked} regtest UFVK components ran");
}

/// The mirror of the test above: regtest reuses testnet's b58 prefixes, so the
/// transparent address is the one field that does not move across the pair.
/// This fails the day upstream gives regtest its own prefix.
#[test]
fn a_regtest_transparent_address_is_a_testnet_address() {
    let seed: Vec<u8> = (0u8..32).collect();
    let address_on = |network| {
        let wallet = Wallet {
            network,
            root: RootSecret::Seed(Zeroizing::new(seed.clone())),
        };
        let mut p = params(0, 0, None);
        p.network = network;
        derive(&wallet, &p, false)
            .expect("view")
            .transparent_address
            .expect("index 0 reaches a transparent child")
    };

    assert_eq!(address_on(Network::Test), address_on(Network::Regtest));
}

#[test]
fn transparent_receiver_is_refused_above_the_bip32_limit() {
    let seed: Vec<u8> = (0u8..32).collect();
    let wallet = seed_wallet(&seed);
    // ZIP-316 forbids a transparent-only Unified Address, so pair it with a
    // shielded receiver the derivation can actually satisfy.
    let params = params(0, 1 << 31, Some(vec![Pool::Sapling, Pool::P2pkh]));

    let error = derive(&wallet, &params, false).expect_err("no transparent child exists");
    assert!(
        error.to_string().contains("no transparent child"),
        "unexpected error: {error}"
    );
}

#[test]
fn unhardened_paths_are_refused() {
    let error = derivator::view::parse_path("m/32'/133'/0").expect_err("must be hardened");
    assert!(error.to_string().contains("not hardened"), "{error}");
}
