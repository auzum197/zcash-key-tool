use anyhow::{Result, anyhow, bail};
use bip0039::{English, Mnemonic};
use secrecy::SecretString;
use std::io::IsTerminal;
use std::path::Path;
use zcash_keys::keys::{UnifiedFullViewingKey, UnifiedIncomingViewingKey};
use zcash_protocol::consensus::NetworkConstants;
use zeroize::Zeroizing;

use crate::cli::{
    CreateArgs, DeriveArgs, DisplayArgs, ImportArgs, ImportKind, RekeyArgs, RevealArgs, StdinKind,
    ViewArgs, WordCount,
};
use crate::envelope::{self, KdfParams};
use crate::input::{self, PassphraseSource};
use crate::network::Network;
use crate::render;
use crate::storage;
use crate::view::{self, Derivation, Field, ViewParams};
use crate::wallet::{RootSecret, SAPLING_EXTSK_LEN, Wallet};

fn open(path: &Path, source: &PassphraseSource) -> Result<Wallet> {
    let file = storage::read(path)?;
    let passphrase = source.read("File Passphrase", false)?;
    let (body, _) = envelope::decrypt(&passphrase, &file)?;
    Wallet::decode(&body)
}

fn save(
    path: &Path,
    wallet: &Wallet,
    source: &PassphraseSource,
    kdf: KdfParams,
    force: bool,
) -> Result<()> {
    let passphrase = source.read("New File Passphrase", true)?;
    let file = envelope::encrypt(&passphrase, &wallet.encode()?, kdf)?;
    storage::write_atomically(path, &file, force)
}

/// The account 0 view of a Wallet File that was just written. It is derived
/// even when nothing will be printed: reaching an address is the last check
/// that the Root Secret now on disk is one the read verbs can use.
fn first_view(wallet: &Wallet) -> Result<Derivation> {
    view::derive(
        wallet,
        &ViewParams {
            network: wallet.network,
            account: 0,
            diversifier_index: 0,
            index_given: false,
            scope: zip32::Scope::External,
            receivers: None,
            path: None,
        },
        false,
    )
}

fn seed_passphrase(prompt_for_one: bool) -> Result<SecretString> {
    if prompt_for_one {
        input::read_secret_line("Seed Passphrase (BIP-39)")
    } else {
        Ok(SecretString::from(String::new()))
    }
}

/// A fresh Mnemonic Root Secret. `create` seals it in a Wallet File. `reveal
/// --new` prints it.
fn generate_wallet(
    words: WordCount,
    network: Network,
    seed_passphrase_flag: bool,
) -> Result<Wallet> {
    let mnemonic = Mnemonic::<English>::generate(words.into());
    Ok(Wallet {
        network,
        root: RootSecret::Mnemonic {
            entropy: Zeroizing::new(mnemonic.entropy().to_vec()),
            seed_passphrase: seed_passphrase(seed_passphrase_flag)?,
        },
    })
}

/// Resolve the flags into derivation parameters, refusing a Network override
/// on Root Secrets whose encoding already fixes it.
fn params(args: &ViewArgs, wallet: &Wallet) -> Result<ViewParams> {
    let network = match args.network.map(Network::from) {
        Some(requested) if wallet.root.network_is_intrinsic() && requested != wallet.network => {
            bail!(
                "this Wallet File holds a {} {}, whose network was fixed when it was imported",
                wallet.network.label(),
                wallet.root.kind()
            )
        }
        Some(requested) => requested,
        None => wallet.network,
    };

    if args.account.is_some()
        && !matches!(
            wallet.root,
            RootSecret::Mnemonic { .. } | RootSecret::Seed(_)
        )
    {
        bail!(
            "--account has no effect on a {} Root Secret: its account was fixed when the key was derived",
            wallet.root.kind()
        );
    }

    Ok(ViewParams {
        network,
        account: args.account.unwrap_or(0),
        diversifier_index: args.diversifier_index.unwrap_or(0),
        index_given: args.diversifier_index.is_some(),
        scope: args.scope.into(),
        receivers: args.receivers.clone(),
        path: args.path.as_deref().map(view::parse_path).transpose()?,
    })
}

pub fn create(args: CreateArgs) -> Result<()> {
    let wallet = generate_wallet(args.words, args.network.into(), args.seed_passphrase)?;

    save(
        &args.file,
        &wallet,
        &args.passphrase,
        args.kdf_cost.into(),
        args.force,
    )?;

    let view = first_view(&wallet)?;
    if args.output.wanted() {
        render::print(&view, args.output.json)?;
    }

    eprintln!(
        "Wrote {}. Run `zkeytool reveal -f {}` to record your Mnemonic.",
        args.file.display(),
        args.file.display()
    );
    Ok(())
}

/// Work out which network an imported encoding belongs to from its prefix.
fn network_of<'a>(encoding: &str, hrp: impl Fn(&Network) -> &'a str) -> Option<Network> {
    Network::ALL
        .into_iter()
        .filter(|network| encoding.starts_with(hrp(network)))
        // "uview" and "uivk" are prefixes of both their test and regtest
        // siblings, so the longest match is the only right one. The three
        // "secret-extended-key-*" are prefix-free and never reach the tie.
        .max_by_key(|network| hrp(network).len())
}

fn import_key(encoding: &str) -> Result<Wallet> {
    let encoding = encoding.trim();

    if let Some(network) = network_of(encoding, |n| n.hrp_unified_fvk()) {
        UnifiedFullViewingKey::decode(&network, encoding)
            .map_err(|e| anyhow!("not a valid UFVK: {e}"))?;
        return Ok(Wallet {
            network,
            root: RootSecret::Ufvk(encoding.to_owned()),
        });
    }

    if let Some(network) = network_of(encoding, |n| n.hrp_unified_ivk()) {
        UnifiedIncomingViewingKey::decode(&network, encoding)
            .map_err(|e| anyhow!("not a valid UIVK: {e}"))?;
        return Ok(Wallet {
            network,
            root: RootSecret::Uivk(encoding.to_owned()),
        });
    }

    if let Some(network) = network_of(encoding, |n| n.hrp_sapling_extended_spending_key()) {
        let extsk = zcash_keys::encoding::decode_extended_spending_key(
            network.hrp_sapling_extended_spending_key(),
            encoding,
        )
        .map_err(|e| anyhow!("not a valid Sapling extended spending key: {e}"))?;
        let mut bytes = Zeroizing::new(vec![0u8; SAPLING_EXTSK_LEN]);
        bytes.copy_from_slice(&extsk.to_bytes());
        return Ok(Wallet {
            network,
            root: RootSecret::SaplingExtendedSpendingKey(bytes),
        });
    }

    bail!("unrecognised key encoding: expected uview…, uivk…, or secret-extended-key-…")
}

pub fn import(args: ImportArgs) -> Result<()> {
    let network = args.network.map(Network::from).unwrap_or(Network::Main);
    let wallet = match args.from {
        ImportKind::Mnemonic => {
            let phrase = input::read_secret_line("Mnemonic")?;
            let mnemonic = mnemonic_from(&phrase)?;
            Wallet {
                network,
                root: RootSecret::Mnemonic {
                    entropy: Zeroizing::new(mnemonic.entropy().to_vec()),
                    seed_passphrase: seed_passphrase(args.seed_passphrase)?,
                },
            }
        }
        ImportKind::Seed => {
            let raw = input::read_secret_line("Seed (hex)")?;
            use secrecy::ExposeSecret;
            Wallet {
                network,
                root: RootSecret::Seed(view::seed_from_hex(raw.expose_secret())?),
            }
        }
        ImportKind::Key => {
            let raw = input::read_secret_line("Key")?;
            use secrecy::ExposeSecret;
            let wallet = import_key(raw.expose_secret())?;
            if let Some(requested) = args.network.map(Network::from)
                && requested != wallet.network
            {
                bail!(
                    "--network {} contradicts this {} {}",
                    requested.label(),
                    wallet.network.label(),
                    wallet.root.kind()
                )
            }
            wallet
        }
    };

    save(
        &args.file,
        &wallet,
        &args.passphrase,
        args.kdf_cost.into(),
        args.force,
    )?;

    let view = first_view(&wallet)?;
    if args.output.wanted() {
        render::print(&view, args.output.json)?;
    }

    eprintln!("Wrote {}.", args.file.display());
    Ok(())
}

fn mnemonic_from(phrase: &SecretString) -> Result<Mnemonic<English>> {
    use secrecy::ExposeSecret;
    Mnemonic::<English>::from_phrase(phrase.expose_secret().trim().to_owned())
        .map_err(|e| anyhow!("not a valid BIP-39 Mnemonic: {e}"))
}

pub fn display(args: DisplayArgs) -> Result<()> {
    let wallet = open(&args.file, &args.passphrase)?;
    let params = params(&args.view, &wallet)?;
    let view = view::derive(&wallet, &params, false)?;

    // `--all` restores the full text dump. `--json` on its own the full JSON
    // dump (both today's surfaces, unchanged). Otherwise extract one field,
    // defaulting to the Unified Address, `--json` picking JSON over raw framing.
    if args.all {
        render::print(&view, false)
    } else if args.view.json && args.field.is_none() {
        render::print(&view, true)
    } else if args.qr {
        render::qr(&view, args.field.unwrap_or(Field::Ua))
    } else {
        render::field(&view, args.field.unwrap_or(Field::Ua), args.view.json)
    }
}

fn from_stdin(kind: StdinKind, network: Network, prompt_for_passphrase: bool) -> Result<Wallet> {
    use secrecy::ExposeSecret;
    let root = match kind {
        StdinKind::Mnemonic => {
            let phrase = input::read_secret_line("Mnemonic")?;
            RootSecret::Mnemonic {
                entropy: Zeroizing::new(mnemonic_from(&phrase)?.entropy().to_vec()),
                seed_passphrase: seed_passphrase(prompt_for_passphrase)?,
            }
        }
        StdinKind::Seed => {
            let raw = input::read_secret_line("Seed (hex)")?;
            RootSecret::Seed(view::seed_from_hex(raw.expose_secret())?)
        }
    };
    Ok(Wallet { network, root })
}

pub fn reveal(args: RevealArgs) -> Result<()> {
    if !std::io::stdout().is_terminal() && !args.allow_redirect {
        bail!("stdout is not a terminal: pass --allow-redirect to write secrets anyway");
    }

    let wallet = if args.new {
        let network = args
            .view
            .network
            .map(Network::from)
            .unwrap_or(Network::Main);
        generate_wallet(args.words, network, args.seed_passphrase)?
    } else if let Some(path) = &args.file {
        open(path, &args.passphrase)?
    } else if args.stdin {
        let network = args
            .view
            .network
            .map(Network::from)
            .unwrap_or(Network::Main);
        from_stdin(args.from, network, args.seed_passphrase)?
    } else {
        bail!("give --file, --stdin, or --new");
    };

    let params = params(&args.view, &wallet)?;
    let view = view::derive(&wallet, &params, true)?;
    render::print(&view, args.view.json)
}

pub fn derive(args: DeriveArgs) -> Result<()> {
    let network = args
        .view
        .network
        .map(Network::from)
        .unwrap_or(Network::Main);
    let wallet = from_stdin(args.from, network, args.seed_passphrase)?;
    let params = params(&args.view, &wallet)?;
    let view = view::derive(&wallet, &params, false)?;
    render::print(&view, args.view.json)
}

pub fn rekey(args: RekeyArgs) -> Result<()> {
    let file = storage::read(&args.file)?;
    let old = args.passphrase.read("Current File Passphrase", false)?;
    let new = PassphraseSource::from(args.new_passphrase).read("New File Passphrase", true)?;

    let rewrapped = envelope::rekey(&old, &new, &file, args.kdf_cost.into())?;
    storage::write_atomically(&args.file, &rewrapped, true)?;

    eprintln!(
        "Rewrapped {}. The body was not re-encrypted.",
        args.file.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_network_resolves_to_itself_from_its_own_hrp() {
        for network in Network::ALL {
            for hrp in [
                Network::hrp_unified_fvk as fn(&Network) -> &'static str,
                Network::hrp_unified_ivk,
                Network::hrp_sapling_extended_spending_key,
            ] {
                let encoding = format!("{}1qqq", hrp(&network));
                assert_eq!(network_of(&encoding, hrp), Some(network), "{encoding}");
            }
        }
    }
}
