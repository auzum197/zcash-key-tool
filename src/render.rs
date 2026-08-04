use anyhow::{Result, bail};
use clap::ValueEnum;

use crate::view::{Derivation, Field, FieldValue};

const LABEL_WIDTH: usize = 22;

fn row(label: &str, value: &str) {
    println!("{label:<LABEL_WIDTH$}{value}");
}

fn maybe(label: &str, value: &Option<String>) {
    if let Some(value) = value {
        row(label, value);
    }
}

/// Extract one selected field. Raw framing is one record per line, each
/// newline-terminated, no label. JSON framing is one standalone JSON document.
/// An absent scalar bails before any byte reaches stdout, so stdout stays empty
/// on failure and the pipe never sees garbage.
pub fn field(view: &Derivation, field: Field, json: bool) -> Result<()> {
    let value = view.field(field);

    if matches!(value, FieldValue::Text(None) | FieldValue::Number(None)) {
        let name = field
            .to_possible_value()
            .expect("every Field has a canonical name")
            .get_name()
            .to_owned();
        bail!(
            "no value for field '{name}' in this wallet. run 'display --all' to see what's available, or pick another field with --field"
        );
    }

    if json {
        let document = match &value {
            FieldValue::Text(Some(text)) => serde_json::to_string(text)?,
            FieldValue::Number(Some(number)) => serde_json::to_string(number)?,
            FieldValue::List(items) => serde_json::to_string(items)?,
            _ => unreachable!("absent scalars bailed above"),
        };
        println!("{document}");
    } else {
        match &value {
            FieldValue::Text(Some(text)) => println!("{text}"),
            FieldValue::Number(Some(number)) => println!("{number}"),
            FieldValue::List(items) => items.iter().for_each(|item| println!("{item}")),
            _ => unreachable!("absent scalars bailed above"),
        }
    }
    Ok(())
}

pub fn print(view: &Derivation, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(view)?);
        return Ok(());
    }

    row("network", view.network);
    row("root secret", view.root_secret);
    row("capability", view.capability);
    row("pool coverage", &view.pool_coverage.join(", "));
    maybe("seed fingerprint", &view.seed_fingerprint);

    println!();
    if let Some(account) = view.account {
        row("account", &account.to_string());
    }
    maybe("path", &view.path);
    row("scope", view.scope);
    maybe("diversifier index", &view.diversifier_index);

    println!();
    maybe("unified address", &view.unified_address);
    if !view.address_receivers.is_empty() {
        row("  receivers", &view.address_receivers.join(", "));
    }
    maybe("transparent address", &view.transparent_address);

    println!();
    maybe("ufvk", &view.ufvk);
    maybe("uivk", &view.uivk);
    maybe("sapling extfvk", &view.sapling_extended_full_viewing_key);

    for note in &view.notes {
        println!("\nnote: {note}");
    }

    if let Some(secrets) = &view.secrets {
        println!("\n--- secret material ---");
        maybe("mnemonic", &secrets.mnemonic);
        maybe("seed", &secrets.seed_hex);
        maybe("sapling extsk", &secrets.sapling_extended_spending_key);
        maybe("orchard sk", &secrets.orchard_spending_key_hex);
    }

    Ok(())
}
