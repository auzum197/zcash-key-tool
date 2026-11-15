use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use zip32::Scope;

use crate::envelope::KdfParams;
use crate::input::PassphraseSource;
use crate::network::Network;
use crate::view::{Field, Pool};

#[derive(Parser, Debug)]
#[command(
    name = "derivator",
    about = "Offline Zcash key derivation",
    long_about = "Creates, imports and inspects Zcash key material. Never touches the network."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Generate a new Root Secret and write an encrypted Wallet File
    Create(CreateArgs),
    /// Write a Wallet File from an existing Mnemonic, seed, or key
    Import(ImportArgs),
    /// Show addresses and viewing keys for a Wallet File
    Display(DisplayArgs),
    /// Print secret material. The only command that does.
    Reveal(RevealArgs),
    /// Derive from a Mnemonic or seed read on stdin, writing no file
    Derive(DeriveArgs),
    /// Change the File Passphrase of a Wallet File
    Rekey(RekeyArgs),
}

#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum NetworkArg {
    Main,
    Test,
    Regtest,
}

impl From<NetworkArg> for Network {
    fn from(arg: NetworkArg) -> Self {
        match arg {
            NetworkArg::Main => Network::Main,
            NetworkArg::Test => Network::Test,
            NetworkArg::Regtest => Network::Regtest,
        }
    }
}

#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum ScopeArg {
    External,
    Internal,
}

impl From<ScopeArg> for Scope {
    fn from(arg: ScopeArg) -> Self {
        match arg {
            ScopeArg::External => Scope::External,
            ScopeArg::Internal => Scope::Internal,
        }
    }
}

#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum KdfCost {
    Fast,
    Standard,
    Paranoid,
}

impl From<KdfCost> for KdfParams {
    fn from(cost: KdfCost) -> Self {
        match cost {
            KdfCost::Fast => KdfParams::FAST,
            KdfCost::Standard => KdfParams::STANDARD,
            KdfCost::Paranoid => KdfParams::PARANOID,
        }
    }
}

#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum WordCount {
    #[value(name = "12")]
    W12,
    #[value(name = "15")]
    W15,
    #[value(name = "18")]
    W18,
    #[value(name = "21")]
    W21,
    #[value(name = "24")]
    W24,
}

impl From<WordCount> for bip0039::Count {
    fn from(count: WordCount) -> Self {
        match count {
            WordCount::W12 => Self::Words12,
            WordCount::W15 => Self::Words15,
            WordCount::W18 => Self::Words18,
            WordCount::W21 => Self::Words21,
            WordCount::W24 => Self::Words24,
        }
    }
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImportKind {
    /// A BIP-39 word sequence
    Mnemonic,
    /// Raw seed bytes as hex
    Seed,
    /// uview…, uivk…, or secret-extended-key-…
    Key,
}

/// Flags shared by every command that derives a view of a Root Secret.
#[derive(Args, Debug, Clone)]
pub struct ViewArgs {
    /// Override the Network stored in the Wallet File
    #[arg(long, value_enum)]
    pub network: Option<NetworkArg>,

    /// ZIP-32 account index
    #[arg(long, group = "derivation-surface")]
    pub account: Option<u32>,

    /// Which address within the account to show. Without it, the first index
    /// that yields every available receiver is used.
    #[arg(long)]
    pub diversifier_index: Option<u128>,

    /// Receive addresses or change addresses
    #[arg(long, value_enum, default_value = "external")]
    pub scope: ScopeArg,

    /// Restrict the Unified Address to these receivers
    #[arg(long, value_enum, value_delimiter = ',')]
    pub receivers: Option<Vec<Pool>>,

    /// Derive along a literal ZIP-32 path instead of by account
    #[arg(long, group = "derivation-surface", value_name = "m/32'/133'/0'")]
    pub path: Option<String>,

    /// Emit the documented JSON schema instead of text
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct CreateArgs {
    /// Where to write the Wallet File
    #[arg(short, long)]
    pub file: PathBuf,

    /// Length of the generated Mnemonic
    #[arg(long, value_enum, default_value = "24")]
    pub words: WordCount,

    /// Network stored as this wallet's default
    #[arg(long, value_enum, default_value = "main")]
    pub network: NetworkArg,

    /// Also prompt for a BIP-39 Seed Passphrase
    #[arg(long)]
    pub seed_passphrase: bool,

    #[arg(long, value_enum, default_value = "standard")]
    pub kdf_cost: KdfCost,

    /// Replace an existing file
    #[arg(long)]
    pub force: bool,

    #[command(flatten)]
    pub passphrase: PassphraseSource,

    #[command(flatten)]
    pub output: WriteOutput,
}

/// A write verb says nothing on stdout unless asked. `display` is the read
/// verb. These only report where the file went, and that goes to stderr.
#[derive(Args, Debug)]
pub struct WriteOutput {
    /// Print the resulting account 0 view as the documented JSON schema
    #[arg(long, group = "write-output")]
    pub json: bool,

    /// Print the resulting account 0 view as text
    #[arg(long, group = "write-output")]
    pub show: bool,
}

impl WriteOutput {
    pub fn wanted(&self) -> bool {
        self.json || self.show
    }
}

#[derive(Args, Debug)]
pub struct ImportArgs {
    #[arg(short, long)]
    pub file: PathBuf,

    /// What kind of material is being read
    #[arg(long, value_enum)]
    pub from: ImportKind,

    /// Network stored as this wallet's default (main). Key imports take theirs
    /// from the encoding and refuse a value that disagrees.
    #[arg(long, value_enum)]
    pub network: Option<NetworkArg>,

    /// Also prompt for a BIP-39 Seed Passphrase
    #[arg(long)]
    pub seed_passphrase: bool,

    #[arg(long, value_enum, default_value = "standard")]
    pub kdf_cost: KdfCost,

    #[arg(long)]
    pub force: bool,

    #[command(flatten)]
    pub passphrase: PassphraseSource,

    #[command(flatten)]
    pub output: WriteOutput,
}

#[derive(Args, Debug)]
pub struct DisplayArgs {
    #[arg(short, long)]
    pub file: PathBuf,

    /// Value to extract [default: ua]
    // Left as an `Option` rather than a `default_value`: a bare `display` and an
    // explicit `--field ua` must share the raw path, yet `--json` on its own has
    // to mean the full dump, not the `ua` scalar. Only the absence of the flag
    // tells those two apart.
    #[arg(long, value_enum)]
    pub field: Option<Field>,

    /// Full human-readable dump of every field
    #[arg(long)]
    pub all: bool,

    /// Render the selected field as a QR code for the terminal
    #[arg(long, conflicts_with_all = ["json", "all"])]
    pub qr: bool,

    #[command(flatten)]
    pub view: ViewArgs,

    #[command(flatten)]
    pub passphrase: PassphraseSource,
}

#[derive(Args, Debug)]
pub struct RevealArgs {
    #[arg(short, long, group = "reveal-source")]
    pub file: Option<PathBuf>,

    /// Read a Mnemonic or hex seed from stdin instead of opening a file
    #[arg(long, group = "reveal-source")]
    pub stdin: bool,

    /// Generate a fresh Root Secret in-place
    #[arg(long, group = "reveal-source")]
    pub new: bool,

    /// Length of the Mnemonic generated by --new
    #[arg(long, value_enum, default_value = "24")]
    pub words: WordCount,

    /// Print secrets even though stdout is redirected
    #[arg(long)]
    pub allow_redirect: bool,

    /// What kind of material stdin carries
    #[arg(long, value_enum, default_value = "mnemonic")]
    pub from: StdinKind,

    /// Also prompt for a BIP-39 Seed Passphrase
    #[arg(long)]
    pub seed_passphrase: bool,

    #[command(flatten)]
    pub view: ViewArgs,

    #[command(flatten)]
    pub passphrase: PassphraseSource,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum StdinKind {
    Mnemonic,
    Seed,
}

#[derive(Args, Debug)]
pub struct DeriveArgs {
    /// What kind of material stdin carries
    #[arg(long, value_enum, default_value = "mnemonic")]
    pub from: StdinKind,

    /// Also prompt for a BIP-39 Seed Passphrase
    #[arg(long)]
    pub seed_passphrase: bool,

    #[command(flatten)]
    pub view: ViewArgs,
}

#[derive(Args, Debug)]
pub struct RekeyArgs {
    #[arg(short, long)]
    pub file: PathBuf,

    /// Re-derive the key-encrypting key at this cost
    #[arg(long, value_enum, default_value = "standard")]
    pub kdf_cost: KdfCost,

    #[command(flatten)]
    pub passphrase: PassphraseSource,

    #[command(flatten)]
    pub new_passphrase: NewPassphraseSource,
}

#[derive(Args, Debug, Clone)]
pub struct NewPassphraseSource {
    /// Read the new File Passphrase from a file
    #[arg(long, value_name = "PATH", group = "new_file_passphrase_source")]
    pub new_file_passphrase_file: Option<PathBuf>,

    /// Read the new File Passphrase from an open file descriptor
    #[arg(long, value_name = "FD", group = "new_file_passphrase_source")]
    pub new_file_passphrase_fd: Option<i32>,
}

impl From<NewPassphraseSource> for PassphraseSource {
    fn from(source: NewPassphraseSource) -> Self {
        Self {
            file_passphrase_file: source.new_file_passphrase_file,
            file_passphrase_fd: source.new_file_passphrase_fd,
        }
    }
}
