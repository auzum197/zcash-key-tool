//! End-to-end runs of the binary, over a real Wallet File on disk.

use serde_json::Value;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

struct Fixture {
    dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let fixture = Self {
            dir: tempfile::tempdir().expect("temp dir"),
        };
        fixture.write_passphrase("pass.txt", "opening night");
        fixture.write_passphrase("new.txt", "closing night");
        fixture
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn write_passphrase(&self, name: &str, value: &str) {
        std::fs::write(self.path(name), value).expect("write passphrase file");
    }

    fn run(&self, args: &[&str]) -> Output {
        self.run_with_stdin(args, "")
    }

    fn run_with_stdin(&self, args: &[&str], stdin: &str) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_derivator"))
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("binary runs");
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(stdin.as_bytes())
            .expect("write stdin");
        child.wait_with_output().expect("binary exits")
    }

    fn json(&self, args: &[&str]) -> Value {
        self.json_with_stdin(args, "")
    }

    fn json_with_stdin(&self, args: &[&str], stdin: &str) -> Value {
        let output = self.run_with_stdin(args, stdin);
        assert!(
            output.status.success(),
            "{args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).expect("json output")
    }
}

fn as_str(value: &Value, key: &str) -> String {
    value[key].as_str().unwrap_or_default().to_owned()
}

fn wallet(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

const SEED_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

/// (mnemonic, seed) of the first vendored Trezor vector. Its Seed Passphrase
/// is "TREZOR", like every row in that suite.
fn trezor_vector_0() -> (String, String) {
    let raw = std::fs::read_to_string(format!(
        "{}/tests/vectors/bip39_trezor_english.json",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("vendored");
    let rows: Vec<Vec<String>> = serde_json::from_str(&raw).expect("rows");
    (rows[0][1].clone(), rows[0][2].clone())
}

#[test]
fn a_created_wallet_survives_a_passphrase_rotation() {
    let fixture = Fixture::new();
    let file = wallet(&fixture.path("w.wallet"));
    let pass = wallet(&fixture.path("pass.txt"));
    let new = wallet(&fixture.path("new.txt"));

    let created = fixture.json(&[
        "create",
        "-f",
        &file,
        "--kdf-cost",
        "fast",
        "--file-passphrase-file",
        &pass,
        "--json",
    ]);
    let fingerprint = as_str(&created, "seed_fingerprint");
    assert_eq!(fingerprint.len(), 64);
    assert!(
        created.get("secrets").is_none(),
        "create must not print secret material"
    );

    let rotated = fixture.run(&[
        "rekey",
        "-f",
        &file,
        "--kdf-cost",
        "fast",
        "--file-passphrase-file",
        &pass,
        "--new-file-passphrase-file",
        &new,
    ]);
    assert!(rotated.status.success());

    let stale = fixture.run(&[
        "display",
        "-f",
        &file,
        "--file-passphrase-file",
        &pass,
        "--json",
    ]);
    assert!(
        !stale.status.success(),
        "the old passphrase still opened it"
    );

    let opened = fixture.json(&[
        "display",
        "-f",
        &file,
        "--file-passphrase-file",
        &new,
        "--json",
    ]);
    assert_eq!(as_str(&opened, "seed_fingerprint"), fingerprint);
}

#[test]
fn reveal_refuses_a_redirected_stdout() {
    let fixture = Fixture::new();
    let file = wallet(&fixture.path("w.wallet"));
    let pass = wallet(&fixture.path("pass.txt"));

    fixture.json(&[
        "create",
        "-f",
        &file,
        "--kdf-cost",
        "fast",
        "--file-passphrase-file",
        &pass,
        "--json",
    ]);

    let refused = fixture.run(&[
        "reveal",
        "-f",
        &file,
        "--file-passphrase-file",
        &pass,
        "--json",
    ]);
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("--allow-redirect"),
        "the refusal should name the escape hatch"
    );
}

#[test]
fn a_revealed_mnemonic_reimports_to_the_same_wallet() {
    let fixture = Fixture::new();
    let file = wallet(&fixture.path("w.wallet"));
    let copy = wallet(&fixture.path("copy.wallet"));
    let pass = wallet(&fixture.path("pass.txt"));

    let created = fixture.json(&[
        "create",
        "-f",
        &file,
        "--words",
        "12",
        "--kdf-cost",
        "fast",
        "--file-passphrase-file",
        &pass,
        "--json",
    ]);

    let revealed = fixture.json(&[
        "reveal",
        "-f",
        &file,
        "--file-passphrase-file",
        &pass,
        "--allow-redirect",
        "--json",
    ]);
    let mnemonic = as_str(&revealed["secrets"], "mnemonic");
    assert_eq!(mnemonic.split_whitespace().count(), 12);

    let reimported = fixture.json_with_stdin(
        &[
            "import",
            "-f",
            &copy,
            "--from",
            "mnemonic",
            "--kdf-cost",
            "fast",
            "--file-passphrase-file",
            &pass,
            "--json",
        ],
        &mnemonic,
    );

    assert_eq!(
        as_str(&reimported, "seed_fingerprint"),
        as_str(&created, "seed_fingerprint")
    );
    assert_eq!(
        as_str(&reimported, "unified_address"),
        as_str(&created, "unified_address")
    );
}

#[test]
fn an_imported_ufvk_is_watch_only_and_network_locked() {
    let fixture = Fixture::new();
    let file = wallet(&fixture.path("w.wallet"));
    let watch = wallet(&fixture.path("watch.wallet"));
    let pass = wallet(&fixture.path("pass.txt"));

    let created = fixture.json(&[
        "create",
        "-f",
        &file,
        "--kdf-cost",
        "fast",
        "--file-passphrase-file",
        &pass,
        "--json",
    ]);
    let ufvk = as_str(&created, "ufvk");

    let imported = fixture.json_with_stdin(
        &[
            "import",
            "-f",
            &watch,
            "--from",
            "key",
            "--kdf-cost",
            "fast",
            "--file-passphrase-file",
            &pass,
            "--json",
        ],
        &ufvk,
    );
    assert_eq!(as_str(&imported, "root_secret"), "ufvk");
    assert_eq!(as_str(&imported, "capability"), "full-view");

    let revealed = fixture.json(&[
        "reveal",
        "-f",
        &watch,
        "--file-passphrase-file",
        &pass,
        "--allow-redirect",
        "--json",
    ]);
    assert!(
        revealed.get("secrets").is_none(),
        "a viewing key has nothing to reveal"
    );

    let overridden = fixture.run(&[
        "display",
        "-f",
        &watch,
        "--file-passphrase-file",
        &pass,
        "--network",
        "test",
    ]);
    assert!(!overridden.status.success());
    assert!(String::from_utf8_lossy(&overridden.stderr).contains("was fixed when it was imported"));

    let with_account = fixture.run(&[
        "display",
        "-f",
        &watch,
        "--file-passphrase-file",
        &pass,
        "--account",
        "1",
    ]);
    assert!(!with_account.status.success());
    assert!(String::from_utf8_lossy(&with_account.stderr).contains("account was fixed"));

    let shown = fixture.json(&[
        "display",
        "-f",
        &watch,
        "--file-passphrase-file",
        &pass,
        "--json",
    ]);
    assert!(
        shown.get("account").is_none(),
        "an imported key cannot know its account"
    );
}

#[test]
fn the_text_renderer_prints_every_section() {
    let fixture = Fixture::new();
    let file = wallet(&fixture.path("w.wallet"));
    let pass = wallet(&fixture.path("pass.txt"));

    let created = fixture.run(&[
        "create",
        "-f",
        &file,
        "--kdf-cost",
        "fast",
        "--file-passphrase-file",
        &pass,
        "--show",
    ]);
    assert!(created.status.success());
    let stdout = String::from_utf8_lossy(&created.stdout);
    for fragment in ["network", "unified address", "seed fingerprint"] {
        assert!(stdout.contains(fragment), "create text lacks {fragment:?}");
    }
    assert!(
        !stdout.contains("secret material"),
        "create printed a secret section"
    );
    assert!(
        String::from_utf8_lossy(&created.stderr).contains("Wrote"),
        "create never said where the file went"
    );

    let displayed = fixture.run(&[
        "display",
        "-f",
        &file,
        "--file-passphrase-file",
        &pass,
        "--all",
        "--diversifier-index",
        "2147483648",
    ]);
    assert!(displayed.status.success());
    let stdout = String::from_utf8_lossy(&displayed.stdout);
    assert!(
        stdout.contains("note: transparent receiver omitted"),
        "the note section never rendered"
    );

    let revealed = fixture.run(&[
        "reveal",
        "-f",
        &file,
        "--file-passphrase-file",
        &pass,
        "--allow-redirect",
    ]);
    assert!(revealed.status.success());
    let stdout = String::from_utf8_lossy(&revealed.stdout);
    for fragment in ["--- secret material ---", "mnemonic", "sapling extsk"] {
        assert!(stdout.contains(fragment), "reveal text lacks {fragment:?}");
    }
}

#[test]
fn the_write_verbs_say_nothing_on_stdout() {
    let fixture = Fixture::new();
    let file = wallet(&fixture.path("w.wallet"));
    let watch = wallet(&fixture.path("watch.wallet"));
    let pass = wallet(&fixture.path("pass.txt"));
    let new = wallet(&fixture.path("new.txt"));

    let created = fixture.run(&[
        "create",
        "-f",
        &file,
        "--kdf-cost",
        "fast",
        "--file-passphrase-file",
        &pass,
    ]);
    assert!(created.status.success());
    assert!(created.stdout.is_empty(), "create wrote to stdout");
    assert!(
        String::from_utf8_lossy(&created.stderr).contains(&file),
        "create never named the file it wrote"
    );

    // The account 0 view still has to derive, so read it back the read way.
    let ufvk = as_str(
        &fixture.json(&[
            "display",
            "-f",
            &file,
            "--file-passphrase-file",
            &pass,
            "--json",
        ]),
        "ufvk",
    );

    let imported = fixture.run_with_stdin(
        &[
            "import",
            "-f",
            &watch,
            "--from",
            "key",
            "--kdf-cost",
            "fast",
            "--file-passphrase-file",
            &pass,
        ],
        &ufvk,
    );
    assert!(imported.status.success());
    assert!(imported.stdout.is_empty(), "import wrote to stdout");
    assert!(
        String::from_utf8_lossy(&imported.stderr).contains(&watch),
        "import never named the file it wrote"
    );

    let rotated = fixture.run(&[
        "rekey",
        "-f",
        &watch,
        "--kdf-cost",
        "fast",
        "--file-passphrase-file",
        &pass,
        "--new-file-passphrase-file",
        &new,
    ]);
    assert!(rotated.status.success());
    assert!(rotated.stdout.is_empty(), "rekey wrote to stdout");
}

#[test]
fn json_and_show_are_mutually_exclusive() {
    let fixture = Fixture::new();
    let file = wallet(&fixture.path("w.wallet"));
    let pass = wallet(&fixture.path("pass.txt"));

    let refused = fixture.run(&[
        "create",
        "-f",
        &file,
        "--kdf-cost",
        "fast",
        "--file-passphrase-file",
        &pass,
        "--json",
        "--show",
    ]);
    assert!(!refused.status.success(), "--json --show was accepted");
    assert!(!file_exists(&file), "the refused run still wrote a file");
}

fn file_exists(path: &str) -> bool {
    Path::new(path).exists()
}

#[test]
fn seed_and_uivk_imports_work_and_garbage_does_not() {
    let fixture = Fixture::new();
    let pass = wallet(&fixture.path("pass.txt"));

    let seeded = fixture.json_with_stdin(
        &[
            "import",
            "-f",
            &wallet(&fixture.path("s.wallet")),
            "--from",
            "seed",
            "--kdf-cost",
            "fast",
            "--file-passphrase-file",
            &pass,
            "--json",
        ],
        SEED_HEX,
    );
    assert_eq!(as_str(&seeded, "root_secret"), "seed");
    assert_eq!(as_str(&seeded, "seed_fingerprint").len(), 64);

    let uivk = as_str(&seeded, "uivk");
    let watching = fixture.json_with_stdin(
        &[
            "import",
            "-f",
            &wallet(&fixture.path("ivk.wallet")),
            "--from",
            "key",
            "--kdf-cost",
            "fast",
            "--file-passphrase-file",
            &pass,
            "--json",
        ],
        &uivk,
    );
    assert_eq!(as_str(&watching, "root_secret"), "uivk");
    assert_eq!(as_str(&watching, "capability"), "incoming-view");

    let garbage = fixture.run_with_stdin(
        &[
            "import",
            "-f",
            &wallet(&fixture.path("g.wallet")),
            "--from",
            "key",
            "--file-passphrase-file",
            &pass,
        ],
        "not-a-key",
    );
    assert!(!garbage.status.success());
    assert!(String::from_utf8_lossy(&garbage.stderr).contains("unrecognised key encoding"));
}

#[test]
fn reveal_needs_a_source() {
    let fixture = Fixture::new();
    let sourceless = fixture.run(&["reveal", "--allow-redirect", "--json"]);
    assert!(!sourceless.status.success());
    assert!(String::from_utf8_lossy(&sourceless.stderr).contains("give --file, --stdin, or --new"));
}

#[test]
fn reveal_new_generates_a_full_secret_without_a_file() {
    let fixture = Fixture::new();
    let generated = fixture.run(&["reveal", "--new", "--allow-redirect", "--json"]);
    assert!(generated.status.success());
    let view: serde_json::Value =
        serde_json::from_slice(&generated.stdout).expect("reveal --new emits JSON");
    assert_eq!(view["root_secret"], "mnemonic");
    assert!(view["unified_address"].as_str().unwrap().starts_with("u1"));
    assert!(view["ufvk"].as_str().unwrap().starts_with("uview1"));
    // The point of --new: the generated Mnemonic comes back so it can be recorded.
    assert!(!view["secrets"]["mnemonic"].as_str().unwrap().is_empty());
}

#[test]
fn a_missing_parent_directory_fails_cleanly() {
    let fixture = Fixture::new();
    let orphan = wallet(&fixture.path("no-such-dir/w.wallet"));
    let pass = wallet(&fixture.path("pass.txt"));

    let failed = fixture.run(&[
        "create",
        "-f",
        &orphan,
        "--kdf-cost",
        "fast",
        "--file-passphrase-file",
        &pass,
        "--json",
    ]);
    assert!(!failed.status.success());
    assert!(String::from_utf8_lossy(&failed.stderr).contains("writing"));
}

#[test]
fn a_piped_seed_passphrase_reaches_derivation() {
    let fixture = Fixture::new();
    let (mnemonic, seed) = trezor_vector_0();

    let revealed = fixture.json_with_stdin(
        &[
            "reveal",
            "--stdin",
            "--seed-passphrase",
            "--allow-redirect",
            "--json",
        ],
        &format!("{mnemonic}\nTREZOR\n"),
    );
    assert_eq!(as_str(&revealed["secrets"], "seed_hex"), seed);
    assert_eq!(as_str(&revealed["secrets"], "mnemonic"), mnemonic);
}

#[test]
fn an_empty_stdin_names_the_missing_line() {
    let fixture = Fixture::new();
    let starved = fixture.run(&["derive", "--from", "mnemonic", "--json"]);
    assert!(!starved.status.success());
    assert!(String::from_utf8_lossy(&starved.stderr).contains("stdin is empty"));
}

#[test]
fn an_empty_file_passphrase_cannot_be_set() {
    let fixture = Fixture::new();
    fixture.write_passphrase("empty.txt", "\n");
    let refused = fixture.run(&[
        "create",
        "-f",
        &wallet(&fixture.path("w.wallet")),
        "--kdf-cost",
        "fast",
        "--file-passphrase-file",
        &wallet(&fixture.path("empty.txt")),
        "--json",
    ]);
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("refusing an empty"));
}

#[test]
fn reveal_prints_matching_secret_material() {
    let fixture = Fixture::new();
    let revealed = fixture.json_with_stdin(
        &[
            "reveal",
            "--stdin",
            "--from",
            "seed",
            "--allow-redirect",
            "--json",
        ],
        SEED_HEX,
    );

    assert_eq!(as_str(&revealed, "root_secret"), "seed");
    let secrets = &revealed["secrets"];
    assert_eq!(as_str(secrets, "seed_hex"), SEED_HEX);
    assert_eq!(as_str(secrets, "orchard_spending_key_hex").len(), 64);
    assert!(
        as_str(secrets, "sapling_extended_spending_key").starts_with("secret-extended-key-main")
    );
    assert!(secrets.get("mnemonic").is_none(), "a raw seed has no words");
}

#[test]
fn a_sapling_extended_spending_key_reimports() {
    let fixture = Fixture::new();
    let file = wallet(&fixture.path("sap.wallet"));
    let pass = wallet(&fixture.path("pass.txt"));

    let revealed = fixture.json_with_stdin(
        &[
            "reveal",
            "--stdin",
            "--from",
            "seed",
            "--allow-redirect",
            "--json",
        ],
        SEED_HEX,
    );
    let extsk = as_str(&revealed["secrets"], "sapling_extended_spending_key");

    let imported = fixture.json_with_stdin(
        &[
            "import",
            "-f",
            &file,
            "--from",
            "key",
            "--kdf-cost",
            "fast",
            "--file-passphrase-file",
            &pass,
            "--json",
        ],
        &extsk,
    );
    assert_eq!(
        as_str(&imported, "root_secret"),
        "sapling-extended-spending-key"
    );
    assert_eq!(as_str(&imported, "capability"), "spend");
    assert_eq!(imported["pool_coverage"], serde_json::json!(["sapling"]));
    assert_eq!(
        imported["address_receivers"],
        serde_json::json!(["sapling"])
    );

    let again = fixture.json(&[
        "reveal",
        "-f",
        &file,
        "--file-passphrase-file",
        &pass,
        "--allow-redirect",
        "--json",
    ]);
    assert_eq!(
        as_str(&again["secrets"], "sapling_extended_spending_key"),
        extsk
    );
}

#[test]
fn wallet_files_are_written_owner_readable_only() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = Fixture::new();
    let file = wallet(&fixture.path("w.wallet"));
    let pass = wallet(&fixture.path("pass.txt"));
    fixture.json(&[
        "create",
        "-f",
        &file,
        "--kdf-cost",
        "fast",
        "--file-passphrase-file",
        &pass,
        "--json",
    ]);

    let mode = std::fs::metadata(fixture.path("w.wallet"))
        .expect("written")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn a_failed_rekey_leaves_the_file_untouched() {
    let fixture = Fixture::new();
    let file = wallet(&fixture.path("w.wallet"));
    let pass = wallet(&fixture.path("pass.txt"));
    let wrong = wallet(&fixture.path("new.txt"));

    fixture.json(&[
        "create",
        "-f",
        &file,
        "--kdf-cost",
        "fast",
        "--file-passphrase-file",
        &pass,
        "--json",
    ]);
    let before = std::fs::read(fixture.path("w.wallet")).expect("readable");

    let failed = fixture.run(&[
        "rekey",
        "-f",
        &file,
        "--kdf-cost",
        "fast",
        "--file-passphrase-file",
        &wrong,
        "--new-file-passphrase-file",
        &wrong,
    ]);
    assert!(!failed.status.success());
    assert_eq!(
        std::fs::read(fixture.path("w.wallet")).expect("readable"),
        before,
        "a failed rekey modified the Wallet File"
    );
}

#[test]
fn force_replaces_an_existing_wallet_file() {
    let fixture = Fixture::new();
    let file = wallet(&fixture.path("w.wallet"));
    let pass = wallet(&fixture.path("pass.txt"));
    let create = [
        "create",
        "-f",
        file.as_str(),
        "--kdf-cost",
        "fast",
        "--file-passphrase-file",
        pass.as_str(),
        "--json",
    ];

    let first = fixture.json(&create);
    let mut forced = create.to_vec();
    forced.push("--force");
    let second = fixture.json(&forced);

    assert_ne!(
        as_str(&first, "seed_fingerprint"),
        as_str(&second, "seed_fingerprint"),
        "--force should have written a fresh Root Secret"
    );
}

#[test]
fn the_passphrase_can_arrive_on_a_file_descriptor() {
    let fixture = Fixture::new();
    let file = wallet(&fixture.path("w.wallet"));
    let pass = wallet(&fixture.path("pass.txt"));
    fixture.json(&[
        "create",
        "-f",
        &file,
        "--kdf-cost",
        "fast",
        "--file-passphrase-file",
        &pass,
        "--json",
    ]);

    // Descriptor 0 is the one descriptor a test can hand over portably.
    let opened = fixture.json_with_stdin(
        &[
            "display",
            "-f",
            &file,
            "--file-passphrase-fd",
            "0",
            "--json",
        ],
        "opening night",
    );
    assert_eq!(as_str(&opened, "seed_fingerprint").len(), 64);
}

#[test]
fn the_json_schema_is_locked_by_golden_files() {
    let fixture = Fixture::new();

    let displayed = fixture.json_with_stdin(&["derive", "--from", "seed", "--json"], SEED_HEX);
    let expected: Value =
        serde_json::from_str(include_str!("golden/display.json")).expect("golden");
    assert_eq!(
        displayed, expected,
        "the display schema drifted: regenerate tests/golden/display.json deliberately"
    );

    let revealed = fixture.json_with_stdin(
        &[
            "reveal",
            "--stdin",
            "--from",
            "seed",
            "--allow-redirect",
            "--json",
        ],
        SEED_HEX,
    );
    let expected: Value = serde_json::from_str(include_str!("golden/reveal.json")).expect("golden");
    assert_eq!(
        revealed, expected,
        "the reveal schema drifted: regenerate tests/golden/reveal.json deliberately"
    );
}

#[test]
fn a_testnet_wallet_roundtrips_and_its_keys_say_test() {
    let fixture = Fixture::new();
    let file = wallet(&fixture.path("t.wallet"));
    let watch = wallet(&fixture.path("twatch.wallet"));
    let sap = wallet(&fixture.path("tsap.wallet"));
    let pass = wallet(&fixture.path("pass.txt"));

    let created = fixture.json(&[
        "create",
        "-f",
        &file,
        "--network",
        "test",
        "--kdf-cost",
        "fast",
        "--file-passphrase-file",
        &pass,
        "--json",
    ]);
    assert_eq!(as_str(&created, "network"), "test");
    assert!(as_str(&created, "unified_address").starts_with("utest1"));
    let ufvk = as_str(&created, "ufvk");
    assert!(ufvk.starts_with("uviewtest1"));

    // "uviewtest…" also starts with "uview", so the import must prefer the
    // longer testnet prefix over a doomed mainnet decode.
    let imported = fixture.json_with_stdin(
        &[
            "import",
            "-f",
            &watch,
            "--from",
            "key",
            "--kdf-cost",
            "fast",
            "--file-passphrase-file",
            &pass,
            "--json",
        ],
        &ufvk,
    );
    assert_eq!(as_str(&imported, "network"), "test");
    assert_eq!(as_str(&imported, "root_secret"), "ufvk");

    let revealed = fixture.json_with_stdin(
        &[
            "reveal",
            "--stdin",
            "--from",
            "seed",
            "--network",
            "test",
            "--allow-redirect",
            "--json",
        ],
        SEED_HEX,
    );
    let extsk = as_str(&revealed["secrets"], "sapling_extended_spending_key");
    assert!(extsk.starts_with("secret-extended-key-test"));

    let sapling = fixture.json_with_stdin(
        &[
            "import",
            "-f",
            &sap,
            "--from",
            "key",
            "--kdf-cost",
            "fast",
            "--file-passphrase-file",
            &pass,
            "--json",
        ],
        &extsk,
    );
    assert_eq!(as_str(&sapling, "network"), "test");
    assert_eq!(
        as_str(&sapling, "root_secret"),
        "sapling-extended-spending-key"
    );
}

#[test]
fn a_key_import_refuses_a_network_that_contradicts_the_encoding() {
    let fixture = Fixture::new();
    let pass = wallet(&fixture.path("pass.txt"));

    let revealed = fixture.json_with_stdin(
        &[
            "reveal",
            "--stdin",
            "--from",
            "seed",
            "--network",
            "test",
            "--allow-redirect",
            "--json",
        ],
        SEED_HEX,
    );
    let extsk = as_str(&revealed["secrets"], "sapling_extended_spending_key");

    // The refusal lands in import_key, before save, so no KDF is paid.
    let refused = fixture.run_with_stdin(
        &[
            "import",
            "-f",
            &wallet(&fixture.path("clash.wallet")),
            "--from",
            "key",
            "--network",
            "regtest",
            "--file-passphrase-file",
            &pass,
        ],
        &extsk,
    );
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stderr)
            .contains("--network regtest contradicts this test sapling-extended-spending-key")
    );
    assert!(!fixture.path("clash.wallet").exists());
}

#[test]
fn the_stateless_verb_writes_no_file() {
    let fixture = Fixture::new();
    let phrase = "abandon abandon abandon abandon abandon abandon \
                  abandon abandon abandon abandon abandon about";

    let derived = fixture.json_with_stdin(&["derive", "--from", "mnemonic", "--json"], phrase);

    assert_eq!(as_str(&derived, "root_secret"), "mnemonic");
    assert!(as_str(&derived, "unified_address").starts_with("u1"));
    assert_eq!(
        std::fs::read_dir(fixture.dir.path())
            .expect("readable")
            .count(),
        2,
        "only the two passphrase files should exist"
    );
}

#[test]
fn a_wallet_file_is_not_overwritten_by_accident() {
    let fixture = Fixture::new();
    let file = wallet(&fixture.path("w.wallet"));
    let pass = wallet(&fixture.path("pass.txt"));
    let create = [
        "create",
        "-f",
        file.as_str(),
        "--kdf-cost",
        "fast",
        "--file-passphrase-file",
        pass.as_str(),
        "--json",
    ];

    let first = fixture.json(&create);
    let second = fixture.run(&create);

    assert!(!second.status.success());
    assert!(String::from_utf8_lossy(&second.stderr).contains("--force"));

    let unchanged = fixture.json(&[
        "display",
        "-f",
        &file,
        "--file-passphrase-file",
        &pass,
        "--json",
    ]);
    assert_eq!(
        as_str(&unchanged, "seed_fingerprint"),
        as_str(&first, "seed_fingerprint")
    );
}

#[test]
fn the_derivation_surface_flags_are_mutually_exclusive() {
    let fixture = Fixture::new();
    let file = wallet(&fixture.path("w.wallet"));
    let pass = wallet(&fixture.path("pass.txt"));

    fixture.json(&[
        "create",
        "-f",
        &file,
        "--kdf-cost",
        "fast",
        "--file-passphrase-file",
        &pass,
        "--json",
    ]);

    let clash = fixture.run(&[
        "display",
        "-f",
        &file,
        "--file-passphrase-file",
        &pass,
        "--account",
        "1",
        "--path",
        "m/32'/133'/1'",
    ]);
    assert!(!clash.status.success());
    assert!(String::from_utf8_lossy(&clash.stderr).contains("cannot be used with"));
}

/// The Unified Address and transparent address the vendored `SEED_HEX` derives,
/// mirrored from `tests/golden/display.json`.
const SEED_UA: &str = "u1m2p65qdnhexpfcmejjf6hjqd485xwfsrlf3cvc6wx5xhwrcq8myrdlqyhdpklz5d87ct0epfty0cr9d6q9fqtycx0j3vdhc2tzmkeejhtdqj3zrjqk3dd5ufpqkmueg89e6a6alvpaaxcx4fxsxqk4yj7g8dayn94d3afrsx66m3vq4rk03hc0ufmtkcm8wca7xja42f9kjau9708z7";
const SEED_TRANSPARENT: &str = "t1V9mnyk5Z5cTNMCkLbaDwSskgJZucTLdgW";

/// Write a deterministic seed-based Wallet File, so extracted values are the
/// known golden ones. Returns its path.
fn seed_wallet(fixture: &Fixture, name: &str) -> String {
    let file = wallet(&fixture.path(name));
    let created = fixture.run_with_stdin(
        &[
            "import",
            "-f",
            &file,
            "--from",
            "seed",
            "--kdf-cost",
            "fast",
            "--file-passphrase-file",
            &wallet(&fixture.path("pass.txt")),
        ],
        SEED_HEX,
    );
    assert!(created.status.success(), "seed import failed");
    file
}

#[test]
fn a_bare_display_extracts_the_unified_address_raw() {
    let fixture = Fixture::new();
    let file = seed_wallet(&fixture, "w.wallet");
    let pass = wallet(&fixture.path("pass.txt"));

    let bare = fixture.run(&["display", "-f", &file, "--file-passphrase-file", &pass]);
    assert!(bare.status.success());
    assert_eq!(
        String::from_utf8_lossy(&bare.stdout),
        format!("{SEED_UA}\n"),
        "bare display is the UA, one raw line, no label"
    );

    // Explicit `--field ua` is byte-identical to the bare invocation.
    let explicit = fixture.run(&[
        "display",
        "-f",
        &file,
        "--file-passphrase-file",
        &pass,
        "--field",
        "ua",
    ]);
    assert_eq!(bare.stdout, explicit.stdout);
}

#[test]
fn a_list_field_is_one_element_per_line() {
    let fixture = Fixture::new();
    let file = seed_wallet(&fixture, "w.wallet");
    let pass = wallet(&fixture.path("pass.txt"));

    let transparent = fixture.run(&[
        "display",
        "-f",
        &file,
        "--file-passphrase-file",
        &pass,
        "--field",
        "transparent",
    ]);
    assert_eq!(
        String::from_utf8_lossy(&transparent.stdout),
        format!("{SEED_TRANSPARENT}\n")
    );

    let receivers = fixture.run(&[
        "display",
        "-f",
        &file,
        "--file-passphrase-file",
        &pass,
        "--field",
        "receivers",
    ]);
    assert!(receivers.status.success());
    assert_eq!(
        String::from_utf8_lossy(&receivers.stdout),
        "orchard\nsapling\np2pkh\n",
        "a list field prints one newline-terminated element per line"
    );
}

#[test]
fn field_json_keeps_the_native_type_and_matches_the_full_dump() {
    let fixture = Fixture::new();
    let file = seed_wallet(&fixture, "w.wallet");
    let pass = wallet(&fixture.path("pass.txt"));

    let raw_json = |field: &str| -> String {
        let out = fixture.run(&[
            "display",
            "-f",
            &file,
            "--file-passphrase-file",
            &pass,
            "--field",
            field,
            "--json",
        ]);
        assert!(out.status.success(), "--field {field} --json failed");
        String::from_utf8_lossy(&out.stdout).into_owned()
    };

    assert_eq!(
        raw_json("ua"),
        format!("\"{SEED_UA}\"\n"),
        "scalar stays quoted"
    );
    assert_eq!(raw_json("account"), "0\n", "a number stays unquoted");
    assert_eq!(raw_json("schema-version"), "1\n");
    assert_eq!(
        raw_json("receivers"),
        "[\"orchard\",\"sapling\",\"p2pkh\"]\n",
        "a list is one compact JSON array, not JSONL"
    );

    // The invariant: `--field <k> --json` is that key, serialized alone.
    let full = fixture.json(&[
        "display",
        "-f",
        &file,
        "--file-passphrase-file",
        &pass,
        "--json",
    ]);
    let alone = serde_json::to_string(&full["unified_address"]).unwrap();
    assert_eq!(raw_json("ua").trim_end(), alone);
}

#[test]
fn an_absent_field_exits_one_with_empty_stdout() {
    let fixture = Fixture::new();
    let pass = wallet(&fixture.path("pass.txt"));

    // A UIVK import carries no full viewing key, so `ufvk` is a valid name with
    // no value here.
    let uivk = as_str(
        &fixture.json_with_stdin(
            &[
                "import",
                "-f",
                &wallet(&fixture.path("s.wallet")),
                "--from",
                "seed",
                "--kdf-cost",
                "fast",
                "--file-passphrase-file",
                &pass,
                "--json",
            ],
            SEED_HEX,
        ),
        "uivk",
    );
    let ivk_file = wallet(&fixture.path("ivk.wallet"));
    fixture.run_with_stdin(
        &[
            "import",
            "-f",
            &ivk_file,
            "--from",
            "key",
            "--kdf-cost",
            "fast",
            "--file-passphrase-file",
            &pass,
        ],
        &uivk,
    );

    let absent = fixture.run(&[
        "display",
        "-f",
        &ivk_file,
        "--file-passphrase-file",
        &pass,
        "--field",
        "ufvk",
    ]);
    assert_eq!(absent.status.code(), Some(1), "absent field exits 1");
    assert!(absent.stdout.is_empty(), "stdout stays empty on failure");
    assert!(
        String::from_utf8_lossy(&absent.stderr).contains("no value for field 'ufvk'"),
        "stderr names the absent field"
    );

    // Absent under --json is still exit 1 with empty stdout, never `null`.
    let absent_json = fixture.run(&[
        "display",
        "-f",
        &ivk_file,
        "--file-passphrase-file",
        &pass,
        "--field",
        "ufvk",
        "--json",
    ]);
    assert_eq!(absent_json.status.code(), Some(1));
    assert!(absent_json.stdout.is_empty());
}

#[test]
fn field_misuse_exits_two_with_a_jq_hint() {
    let fixture = Fixture::new();
    let file = seed_wallet(&fixture, "w.wallet");
    let pass = wallet(&fixture.path("pass.txt"));

    let unknown = fixture.run(&[
        "display",
        "-f",
        &file,
        "--file-passphrase-file",
        &pass,
        "--field",
        "seed",
    ]);
    assert_eq!(
        unknown.status.code(),
        Some(2),
        "unknown field is a usage error"
    );
    assert!(unknown.stdout.is_empty());

    let repeated = fixture.run(&[
        "display",
        "-f",
        &file,
        "--file-passphrase-file",
        &pass,
        "--field",
        "ua",
        "--field",
        "ufvk",
    ]);
    assert_eq!(repeated.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&repeated.stderr)
            .contains("for multiple fields use --json and filter with jq"),
        "a repeated --field points at jq"
    );

    let comma = fixture.run(&[
        "display",
        "-f",
        &file,
        "--file-passphrase-file",
        &pass,
        "--field",
        "ua,ufvk",
    ]);
    assert_eq!(comma.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&comma.stderr).contains("--field takes one field"),
        "a comma list gets the comma-aware hint"
    );
}

#[test]
fn all_and_full_json_are_the_untouched_dumps() {
    let fixture = Fixture::new();
    let file = seed_wallet(&fixture, "w.wallet");
    let pass = wallet(&fixture.path("pass.txt"));

    let all = fixture.run(&[
        "display",
        "-f",
        &file,
        "--file-passphrase-file",
        &pass,
        "--all",
    ]);
    assert!(all.status.success());
    let text = String::from_utf8_lossy(&all.stdout);
    for label in ["network", "unified address", "seed fingerprint"] {
        assert!(text.contains(label), "--all dump lacks {label:?}");
    }

    // `--json` on its own is still the full machine dump.
    let full = fixture.json(&[
        "display",
        "-f",
        &file,
        "--file-passphrase-file",
        &pass,
        "--json",
    ]);
    assert_eq!(as_str(&full, "unified_address"), SEED_UA);
    assert_eq!(as_str(&full, "network"), "main");
}
