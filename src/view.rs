//! Deriving a view of a Root Secret: addresses, viewing keys, and (only for
//! `reveal`) spending keys.

use anyhow::{Result, anyhow, bail};
use serde::Serialize;
use zcash_keys::address::UnifiedAddress;
use zcash_keys::encoding::{
    encode_extended_full_viewing_key, encode_extended_spending_key, encode_transparent_address_p,
};
use zcash_keys::keys::sapling::ExtendedSpendingKey;
use zcash_keys::keys::{
    ReceiverRequirement, UnifiedAddressRequest, UnifiedFullViewingKey, UnifiedIncomingViewingKey,
    UnifiedSpendingKey,
};
use zcash_protocol::consensus::NetworkConstants;
use zcash_transparent::keys::{IncomingViewingKey, NonHardenedChildIndex};
use zeroize::Zeroizing;
use zip32::fingerprint::SeedFingerprint;
use zip32::{AccountId, ChildIndex, DiversifierIndex, Scope};

use crate::network::Network;
use crate::wallet::{PoolCoverage, RootSecret, Wallet};

/// Above this a diversifier index has no matching transparent child, because
/// BIP-32 reserves the top bit for hardened derivation.
const TRANSPARENT_INDEX_LIMIT: u128 = 1 << 31;

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Pool {
    Orchard,
    Sapling,
    #[value(name = "p2pkh", alias = "transparent")]
    P2pkh,
}

/// A single selectable output field. The set is exactly the keys `display
/// --json` emits, 1:1. Secrets are never here: ADR-0004 keeps them in the
/// `reveal`-gated `secrets` sub-struct, outside `Derivation`'s public surface,
/// so they fall out of this namespace structurally. Canonical names are
/// short/kebab. Where a name differs from the snake_case JSON key, that key is
/// a hidden alias so a value copied from `--json` pastes straight in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Field {
    #[value(name = "ua", alias = "unified_address")]
    Ua,
    #[value(name = "transparent", alias = "transparent_address")]
    Transparent,
    Ufvk,
    Uivk,
    #[value(name = "sapling-extfvk", alias = "sapling_extended_full_viewing_key")]
    SaplingExtfvk,
    #[value(name = "receivers", alias = "address_receivers")]
    Receivers,
    #[value(name = "pool-coverage", alias = "pool_coverage")]
    PoolCoverage,
    Network,
    Capability,
    #[value(name = "root-secret", alias = "root_secret")]
    RootSecret,
    #[value(name = "seed-fingerprint", alias = "seed_fingerprint")]
    SeedFingerprint,
    Account,
    Scope,
    #[value(name = "diversifier-index", alias = "diversifier_index")]
    DiversifierIndex,
    Path,
    Notes,
    #[value(name = "schema-version", alias = "schema_version")]
    SchemaVersion,
}

/// One field's value, ready to frame as raw lines or a JSON document.
pub enum FieldValue {
    /// A string scalar. `None` is absent for this wallet (exit 1).
    Text(Option<String>),
    /// A numeric scalar, kept numeric so JSON stays unquoted. `None` is absent.
    Number(Option<u64>),
    /// A list. Always present. Empty is a valid zero-element value (exit 0).
    List(Vec<String>),
}

#[derive(Clone)]
pub struct ViewParams {
    pub network: Network,
    pub account: u32,
    pub diversifier_index: u128,
    /// False when the caller left the index to us, which lets derivation walk
    /// past indices with no valid Sapling diversifier.
    pub index_given: bool,
    pub scope: Scope,
    pub receivers: Option<Vec<Pool>>,
    pub path: Option<Vec<ChildIndex>>,
}

#[derive(Serialize, Debug)]
pub struct Secrets {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mnemonic: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seed_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sapling_extended_spending_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub orchard_spending_key_hex: Option<String>,
}

impl Secrets {
    fn is_empty(&self) -> bool {
        self.mnemonic.is_none()
            && self.seed_hex.is_none()
            && self.sapling_extended_spending_key.is_none()
            && self.orchard_spending_key_hex.is_none()
    }
}

/// A viewing-key Root Secret has nothing to reveal. Say that rather than
/// printing an empty section.
fn attach_secrets(view: &mut Derivation, secrets: Secrets) {
    if secrets.is_empty() {
        view.notes.push(format!(
            "nothing to reveal: a {} Root Secret carries no spending material",
            view.root_secret
        ));
        return;
    }
    view.secrets = Some(secrets);
}

#[derive(Serialize, Debug)]
pub struct Derivation {
    pub schema_version: u32,
    pub network: &'static str,
    pub root_secret: &'static str,
    pub capability: &'static str,
    pub pool_coverage: Vec<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seed_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub scope: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diversifier_index: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unified_address: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub address_receivers: Vec<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transparent_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ufvk: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uivk: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sapling_extended_full_viewing_key: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secrets: Option<Secrets>,
}

impl Derivation {
    /// Resolve one selected field to an extractable value. The mapping is 1:1
    /// with the JSON keys, so `--field <k>` matches `display --json`'s `k`.
    pub fn field(&self, field: Field) -> FieldValue {
        use FieldValue::{List, Number, Text};
        let strings = |labels: &[&str]| labels.iter().map(|s| (*s).to_owned()).collect();
        match field {
            Field::Ua => Text(self.unified_address.clone()),
            Field::Transparent => Text(self.transparent_address.clone()),
            Field::Ufvk => Text(self.ufvk.clone()),
            Field::Uivk => Text(self.uivk.clone()),
            Field::SaplingExtfvk => Text(self.sapling_extended_full_viewing_key.clone()),
            Field::Receivers => List(strings(&self.address_receivers)),
            Field::PoolCoverage => List(strings(&self.pool_coverage)),
            Field::Network => Text(Some(self.network.to_owned())),
            Field::Capability => Text(Some(self.capability.to_owned())),
            Field::RootSecret => Text(Some(self.root_secret.to_owned())),
            Field::SeedFingerprint => Text(self.seed_fingerprint.clone()),
            Field::Account => Number(self.account.map(u64::from)),
            Field::Scope => Text(Some(self.scope.to_owned())),
            Field::DiversifierIndex => Text(self.diversifier_index.clone()),
            Field::Path => Text(self.path.clone()),
            Field::Notes => List(self.notes.clone()),
            Field::SchemaVersion => Number(Some(u64::from(self.schema_version))),
        }
    }
}

fn scope_label(scope: Scope) -> &'static str {
    match scope {
        Scope::External => "external",
        Scope::Internal => "internal",
    }
}

fn wants(receivers: &Option<Vec<Pool>>, pool: Pool) -> bool {
    receivers.as_ref().is_none_or(|list| list.contains(&pool))
}

fn explicitly_wants(receivers: &Option<Vec<Pool>>, pool: Pool) -> bool {
    receivers.as_ref().is_some_and(|list| list.contains(&pool))
}

/// With an explicit `--receivers` list the caller gets exactly that. Otherwise,
/// when we are free to pick the index, require every pool the Root Secret can
/// reach so the address shown is the complete one. At a caller-chosen index we
/// show whatever is valid there instead of refusing.
fn address_request(
    receivers: &Option<Vec<Pool>>,
    pools: PoolCoverage,
    transparent_reachable: bool,
    searching: bool,
) -> Result<UnifiedAddressRequest> {
    let wanted: Vec<Pool> = match receivers {
        None if !searching => return Ok(UnifiedAddressRequest::ALLOW_ALL),
        Some(list) => list.clone(),
        None => [
            (Pool::Orchard, pools.orchard),
            (Pool::Sapling, pools.sapling),
            (Pool::P2pkh, pools.transparent && transparent_reachable),
        ]
        .into_iter()
        .filter_map(|(pool, covered)| covered.then_some(pool))
        .collect(),
    };
    let requirement = |pool| {
        if wanted.contains(&pool) {
            ReceiverRequirement::Require
        } else {
            ReceiverRequirement::Omit
        }
    };
    UnifiedAddressRequest::custom(
        requirement(Pool::Orchard),
        requirement(Pool::Sapling),
        requirement(Pool::P2pkh),
    )
    .map_err(|e| {
        anyhow!(
            "invalid receiver selection ({e:?}): ZIP-316 requires at least one shielded receiver"
        )
    })
}

fn receiver_labels(address: &UnifiedAddress) -> Vec<&'static str> {
    let mut labels = Vec::new();
    if address.has_orchard() {
        labels.push("orchard");
    }
    if address.has_sapling() {
        labels.push("sapling");
    }
    if address.has_transparent() {
        labels.push("p2pkh");
    }
    labels
}

/// Internal (change) addresses have no unified-level constructor, so assemble
/// them receiver by receiver.
fn internal_address(
    ufvk: &UnifiedFullViewingKey,
    j: DiversifierIndex,
    receivers: &Option<Vec<Pool>>,
    notes: &mut Vec<String>,
) -> Result<Option<UnifiedAddress>> {
    let orchard = ufvk
        .orchard()
        .filter(|_| wants(receivers, Pool::Orchard))
        .map(|fvk| fvk.address_at(j, Scope::Internal));

    let sapling = ufvk
        .sapling()
        .filter(|_| wants(receivers, Pool::Sapling))
        .map(|dfvk| {
            let (at, address) = dfvk.change_address();
            if at != j {
                notes.push(format!(
                    "sapling internal addresses are only reachable at their default diversifier index ({}), not {}",
                    u128::from(at),
                    u128::from(j),
                ));
            }
            address
        });

    let transparent = match ufvk.transparent().filter(|_| wants(receivers, Pool::P2pkh)) {
        Some(account_pubkey) => {
            let index = transparent_child(j, receivers, notes)?;
            match index {
                Some(index) => Some(
                    account_pubkey
                        .derive_internal_ivk()
                        .map_err(|e| anyhow!("transparent derivation failed: {e:?}"))?
                        .derive_address(index)
                        .map_err(|e| anyhow!("transparent derivation failed: {e:?}"))?,
                ),
                None => None,
            }
        }
        None => None,
    };

    Ok(UnifiedAddress::from_receivers(
        orchard,
        sapling,
        transparent,
    ))
}

/// A diversifier index above the BIP-32 non-hardened range has no transparent
/// child. Refuse when the caller asked for one, and say so when they did not.
fn check_transparent_reach(
    j: DiversifierIndex,
    receivers: &Option<Vec<Pool>>,
    reachable: bool,
    notes: &mut Vec<String>,
) -> Result<bool> {
    let raw = u128::from(j);
    if !reachable || raw < TRANSPARENT_INDEX_LIMIT {
        return Ok(reachable);
    }
    if explicitly_wants(receivers, Pool::P2pkh) {
        bail!(
            "diversifier index {raw} has no transparent child: BIP-32 non-hardened indices stop at {}",
            TRANSPARENT_INDEX_LIMIT - 1
        );
    }
    notes.push(format!(
        "transparent receiver omitted: diversifier index {raw} is at or above {TRANSPARENT_INDEX_LIMIT}"
    ));
    Ok(false)
}

fn transparent_child(
    j: DiversifierIndex,
    receivers: &Option<Vec<Pool>>,
    notes: &mut Vec<String>,
) -> Result<Option<NonHardenedChildIndex>> {
    if !check_transparent_reach(j, receivers, true, notes)? {
        return Ok(None);
    }
    Ok(NonHardenedChildIndex::from_index(u128::from(j) as u32))
}

fn diversifier(index: u128) -> Result<DiversifierIndex> {
    DiversifierIndex::try_from(index)
        .map_err(|_| anyhow!("diversifier index {index} is out of range (maximum is 2^88 - 1)"))
}

fn account_id(account: u32) -> Result<AccountId> {
    AccountId::try_from(account)
        .map_err(|_| anyhow!("account {account} is out of range (maximum is 2^31 - 1)"))
}

struct Resolved {
    ufvk: Option<UnifiedFullViewingKey>,
    uivk: UnifiedIncomingViewingKey,
    usk: Option<UnifiedSpendingKey>,
}

fn resolve_unified(wallet: &Wallet, network: Network, account: u32) -> Result<Option<Resolved>> {
    if let Some(seed) = wallet.root.seed() {
        let usk = UnifiedSpendingKey::from_seed(&network, &seed, account_id(account)?)
            .map_err(|e| anyhow!("could not derive account {account}: {e:?}"))?;
        let ufvk = usk.to_unified_full_viewing_key();
        let uivk = ufvk.to_unified_incoming_viewing_key();
        return Ok(Some(Resolved {
            ufvk: Some(ufvk),
            uivk,
            usk: Some(usk),
        }));
    }

    match &wallet.root {
        RootSecret::Ufvk(encoding) => {
            let ufvk = UnifiedFullViewingKey::decode(&network, encoding)
                .map_err(|e| anyhow!("stored UFVK does not decode on {}: {e}", network.label()))?;
            let uivk = ufvk.to_unified_incoming_viewing_key();
            Ok(Some(Resolved {
                ufvk: Some(ufvk),
                uivk,
                usk: None,
            }))
        }
        RootSecret::Uivk(encoding) => {
            let uivk = UnifiedIncomingViewingKey::decode(&network, encoding)
                .map_err(|e| anyhow!("stored UIVK does not decode on {}: {e}", network.label()))?;
            Ok(Some(Resolved {
                ufvk: None,
                uivk,
                usk: None,
            }))
        }
        _ => Ok(None),
    }
}

fn coverage(resolved: &Resolved) -> PoolCoverage {
    match &resolved.ufvk {
        Some(ufvk) => PoolCoverage {
            orchard: ufvk.orchard().is_some(),
            sapling: ufvk.sapling().is_some(),
            transparent: ufvk.transparent().is_some(),
        },
        None => PoolCoverage {
            orchard: resolved.uivk.has_orchard(),
            sapling: resolved.uivk.has_sapling(),
            transparent: resolved.uivk.has_transparent(),
        },
    }
}

fn base(wallet: &Wallet, params: &ViewParams) -> Derivation {
    Derivation {
        schema_version: 1,
        network: params.network.label(),
        root_secret: wallet.root.kind(),
        capability: wallet.root.capability().label(),
        pool_coverage: Vec::new(),
        seed_fingerprint: wallet
            .root
            .seed()
            .and_then(|seed| SeedFingerprint::from_seed(&seed))
            .map(|fingerprint| hex::encode(fingerprint.to_bytes())),
        account: None,
        path: None,
        scope: scope_label(params.scope),
        diversifier_index: None,
        unified_address: None,
        address_receivers: Vec::new(),
        transparent_address: None,
        ufvk: None,
        uivk: None,
        sapling_extended_full_viewing_key: None,
        notes: Vec::new(),
        secrets: None,
    }
}

pub fn derive(wallet: &Wallet, params: &ViewParams, reveal: bool) -> Result<Derivation> {
    if params.path.is_some() {
        return derive_by_path(wallet, params, reveal);
    }

    match &wallet.root {
        RootSecret::SaplingExtendedSpendingKey(bytes) => {
            let extsk = ExtendedSpendingKey::from_bytes(bytes)
                .map_err(|e| anyhow!("stored Sapling extended spending key is malformed: {e:?}"))?;
            sapling_only(wallet, params, Some(extsk), reveal)
        }
        _ => derive_unified(wallet, params, reveal),
    }
}

fn derive_unified(wallet: &Wallet, params: &ViewParams, reveal: bool) -> Result<Derivation> {
    let resolved = resolve_unified(wallet, params.network, params.account)?
        .ok_or_else(|| anyhow!("this Root Secret cannot derive unified keys"))?;

    let mut view = base(wallet, params);
    let pools = coverage(&resolved);
    view.pool_coverage = pools.labels();
    // An imported key was derived at an account we cannot know, so only a
    // seed-based Root Secret gets the account it was asked for echoed back.
    if resolved.usk.is_some() {
        view.account = Some(params.account);
    }
    view.diversifier_index = Some(params.diversifier_index.to_string());

    let j = diversifier(params.diversifier_index)?;
    let transparent_reachable =
        check_transparent_reach(j, &params.receivers, pools.transparent, &mut view.notes)?;
    let request = address_request(
        &params.receivers,
        pools,
        transparent_reachable,
        !params.index_given,
    )?;

    let address = match (params.scope, &resolved.ufvk) {
        (Scope::External, Some(ufvk)) => Some(if params.index_given {
            ufvk.address(j, request)
                .map_err(|e| anyhow!("no unified address at that diversifier index: {e:?}"))?
        } else {
            let (address, at) = ufvk
                .find_address(j, request)
                .map_err(|e| anyhow!("no unified address at any diversifier index: {e:?}"))?;
            note_index_search(&mut view, j, at);
            address
        }),
        (Scope::External, None) => Some(if params.index_given {
            resolved
                .uivk
                .address(j, request)
                .map_err(|e| anyhow!("no unified address at that diversifier index: {e:?}"))?
        } else {
            let (address, at) = resolved
                .uivk
                .find_address(j, request)
                .map_err(|e| anyhow!("no unified address at any diversifier index: {e:?}"))?;
            note_index_search(&mut view, j, at);
            address
        }),
        (Scope::Internal, Some(ufvk)) => {
            internal_address(ufvk, j, &params.receivers, &mut view.notes)?
        }
        (Scope::Internal, None) => {
            view.notes.push(
                "internal addresses need a full viewing key, and a UIVK covers only external ones"
                    .to_owned(),
            );
            None
        }
    };

    if let Some(address) = &address {
        view.unified_address = Some(address.encode(&params.network));
        view.address_receivers = receiver_labels(address);
        view.transparent_address = address
            .transparent()
            .map(|t| encode_transparent_address_p(&params.network, t));
        note_absent_receivers(
            &mut view,
            address,
            pools,
            &params.receivers,
            params.diversifier_index,
        );
    }

    if let Some(ufvk) = &resolved.ufvk {
        view.ufvk = Some(ufvk.encode(&params.network));
    }
    // The bech32 `zxviews` encoding needs an ExtendedFullViewingKey, which only
    // the spending key can produce. A UFVK carries the diversifiable form.
    #[allow(deprecated)]
    {
        view.sapling_extended_full_viewing_key = resolved.usk.as_ref().map(|usk| {
            encode_extended_full_viewing_key(
                params.network.hrp_sapling_extended_full_viewing_key(),
                &usk.sapling().to_extended_full_viewing_key(),
            )
        });
    }
    view.uivk = Some(resolved.uivk.encode(&params.network));

    if reveal {
        attach_secrets(
            &mut view,
            unified_secrets(wallet, resolved.usk.as_ref(), params.network),
        );
    }

    Ok(view)
}

/// Record that derivation walked past indices with no valid Sapling diversifier.
fn note_index_search(view: &mut Derivation, from: DiversifierIndex, landed: DiversifierIndex) {
    if from == landed {
        return;
    }
    let landed = u128::from(landed);
    view.diversifier_index = Some(landed.to_string());
    view.notes.push(format!(
        "diversifier index {} has no valid sapling address, so index {landed} was used",
        u128::from(from)
    ));
}

/// A pool the Root Secret covers can still be missing from an address, most
/// often because no valid Sapling diversifier exists at that index.
fn note_absent_receivers(
    view: &mut Derivation,
    address: &UnifiedAddress,
    pools: PoolCoverage,
    receivers: &Option<Vec<Pool>>,
    j: u128,
) {
    let candidates = [
        (
            "orchard",
            pools.orchard,
            address.has_orchard(),
            Pool::Orchard,
        ),
        (
            "sapling",
            pools.sapling,
            address.has_sapling(),
            Pool::Sapling,
        ),
    ];
    for (label, covered, present, pool) in candidates {
        if covered && !present && wants(receivers, pool) {
            view.notes.push(format!(
                "{label} receiver omitted: no valid {label} address at diversifier index {j}"
            ));
        }
    }
}

fn unified_secrets(wallet: &Wallet, usk: Option<&UnifiedSpendingKey>, network: Network) -> Secrets {
    Secrets {
        mnemonic: wallet
            .root
            .mnemonic_phrase()
            .map(|phrase| phrase.to_string()),
        seed_hex: wallet.root.seed().map(|seed| hex::encode(&*seed)),
        sapling_extended_spending_key: usk.map(|usk| {
            encode_extended_spending_key(network.hrp_sapling_extended_spending_key(), usk.sapling())
        }),
        orchard_spending_key_hex: usk.map(|usk| hex::encode(usk.orchard().to_bytes())),
    }
}

/// Derivation from a Sapling extended spending key, which reaches exactly one
/// pool no matter what the caller asked for.
fn sapling_only(
    wallet: &Wallet,
    params: &ViewParams,
    extsk: Option<ExtendedSpendingKey>,
    reveal: bool,
) -> Result<Derivation> {
    let extsk = extsk.ok_or_else(|| anyhow!("no Sapling key available"))?;
    let dfvk = extsk.to_diversifiable_full_viewing_key();

    let mut view = base(wallet, params);
    view.pool_coverage = PoolCoverage::SAPLING_ONLY.labels();

    if params
        .receivers
        .as_ref()
        .is_some_and(|list| list.iter().any(|p| *p != Pool::Sapling))
    {
        view.notes
            .push("this Root Secret reaches only the Sapling pool".to_owned());
    }

    let (index, payment_address) = match params.scope {
        Scope::External => {
            let j = diversifier(params.diversifier_index)?;
            match (params.index_given, dfvk.address(j)) {
                (_, Some(address)) => (j, address),
                (true, None) => bail!(
                    "diversifier index {} has no valid Sapling address",
                    params.diversifier_index
                ),
                (false, None) => {
                    let (at, address) = dfvk.find_address(j).ok_or_else(|| {
                        anyhow!(
                            "no valid Sapling address at or above index {}",
                            params.diversifier_index
                        )
                    })?;
                    note_index_search(&mut view, j, at);
                    (at, address)
                }
            }
        }
        Scope::Internal => dfvk.change_address(),
    };

    view.diversifier_index = Some(u128::from(index).to_string());
    view.unified_address = UnifiedAddress::from_receivers(None, Some(payment_address), None)
        .map(|ua| ua.encode(&params.network));
    view.address_receivers = vec!["sapling"];
    #[allow(deprecated)]
    {
        view.sapling_extended_full_viewing_key = Some(encode_extended_full_viewing_key(
            params.network.hrp_sapling_extended_full_viewing_key(),
            &extsk.to_extended_full_viewing_key(),
        ));
    }

    if reveal {
        view.secrets = Some(Secrets {
            mnemonic: wallet
                .root
                .mnemonic_phrase()
                .map(|phrase| phrase.to_string()),
            seed_hex: wallet.root.seed().map(|seed| hex::encode(&*seed)),
            sapling_extended_spending_key: Some(encode_extended_spending_key(
                params.network.hrp_sapling_extended_spending_key(),
                &extsk,
            )),
            orchard_spending_key_hex: None,
        });
    }

    Ok(view)
}

/// Raw ZIP-32 path derivation. Orchard is unreachable off the standard path
/// because the `orchard` crate exposes no arbitrary-depth derivation.
fn derive_by_path(wallet: &Wallet, params: &ViewParams, reveal: bool) -> Result<Derivation> {
    let path = params
        .path
        .as_ref()
        .ok_or_else(|| anyhow!("no path given"))?;
    let seed = wallet.root.seed().ok_or_else(|| {
        anyhow!(
            "path derivation needs a Mnemonic or a seed, not {}",
            wallet.root.kind()
        )
    })?;

    if let Some(account) = standard_unified_path(path, params.network) {
        let with_account = ViewParams {
            account,
            path: None,
            ..params.clone()
        };
        let mut view = derive_unified(wallet, &with_account, reveal)?;
        view.path = Some(format_path(path));
        return Ok(view);
    }

    let master = ExtendedSpendingKey::master(&seed);
    let extsk = ExtendedSpendingKey::from_path(&master, path);

    let mut view = sapling_only(wallet, params, Some(extsk), reveal)?;
    view.path = Some(format_path(path));
    view.notes.push(
        "off the standard m/32'/coin'/account' path only Sapling and generic ZIP-32 material is derivable, never Orchard"
            .to_owned(),
    );
    Ok(view)
}

fn standard_unified_path(path: &[ChildIndex], network: Network) -> Option<u32> {
    let [purpose, coin, account] = path else {
        return None;
    };
    let expected_coin = ChildIndex::hardened(network.coin_type());
    let expected_purpose = ChildIndex::hardened(32);
    (*purpose == expected_purpose && *coin == expected_coin).then(|| account.index() - (1 << 31))
}

pub fn parse_path(raw: &str) -> Result<Vec<ChildIndex>> {
    let mut segments = raw.split('/');
    if segments.next() != Some("m") {
        bail!("a derivation path starts with 'm', for example m/32'/133'/0'");
    }
    segments
        .map(|segment| {
            let (digits, hardened) = match segment.strip_suffix(['\'', 'h', 'H']) {
                Some(digits) => (digits, true),
                None => (segment, false),
            };
            let index: u32 = digits
                .parse()
                .map_err(|_| anyhow!("'{segment}' is not a derivation path element"))?;
            if !hardened {
                bail!(
                    "'{segment}' is not hardened: ZIP-32 shielded derivation is hardened at every level"
                );
            }
            if index >= 1 << 31 {
                bail!("path element {index} is out of range");
            }
            Ok(ChildIndex::hardened(index))
        })
        .collect()
}

pub fn format_path(path: &[ChildIndex]) -> String {
    let mut out = String::from("m");
    for element in path {
        out.push_str(&format!("/{}'", element.index() - (1 << 31)));
    }
    out
}

pub fn seed_from_hex(raw: &str) -> Result<Zeroizing<Vec<u8>>> {
    let bytes = hex::decode(raw.trim()).map_err(|_| anyhow!("seed is not valid hex"))?;
    crate::wallet::check_seed_len(bytes.len())?;
    Ok(Zeroizing::new(bytes))
}
