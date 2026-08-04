//! Secret input channels. Never argv, never the environment.

use anyhow::{Result, bail};
use secrecy::{ExposeSecret, SecretString};
use std::fs;
use std::io::{BufRead, IsTerminal, Read};
use std::mem::ManuallyDrop;
use std::os::fd::FromRawFd;
use std::path::PathBuf;

#[derive(clap::Args, Debug, Clone)]
pub struct PassphraseSource {
    /// Read the File Passphrase from a file instead of prompting
    #[arg(long, value_name = "PATH", group = "file_passphrase_source")]
    pub file_passphrase_file: Option<PathBuf>,

    /// Read the File Passphrase from an already-open file descriptor
    #[arg(long, value_name = "FD", group = "file_passphrase_source")]
    pub file_passphrase_fd: Option<i32>,
}

fn trim(raw: String) -> SecretString {
    SecretString::from(raw.trim_end_matches(['\n', '\r']).to_owned())
}

fn read_fd(fd: i32) -> Result<String> {
    // The descriptor belongs to the caller, so the File must not close it.
    let mut handle = ManuallyDrop::new(unsafe { fs::File::from_raw_fd(fd) });
    let mut raw = String::new();
    handle.read_to_string(&mut raw)?;
    Ok(raw)
}

impl PassphraseSource {
    /// `confirm` re-prompts and compares, for passphrases that are being set
    /// rather than checked. Non-interactive sources skip the re-prompt: there
    /// is nothing to mistype. Setting an empty passphrase is refused, opening
    /// with one is not, so no existing file can become unreadable.
    pub fn read(&self, prompt: &str, confirm: bool) -> Result<SecretString> {
        let entered = if let Some(path) = &self.file_passphrase_file {
            trim(fs::read_to_string(path)?)
        } else if let Some(fd) = self.file_passphrase_fd {
            trim(read_fd(fd)?)
        } else if std::io::stdin().is_terminal() {
            let entered = SecretString::from(rpassword::prompt_password(format!("{prompt}: "))?);
            if confirm {
                let again = rpassword::prompt_password(format!("{prompt} (again): "))?;
                if again != *entered.expose_secret() {
                    bail!("the two entries do not match");
                }
            }
            entered
        } else {
            bail!("no terminal to prompt on: pass --file-passphrase-file or --file-passphrase-fd");
        };

        if confirm && entered.expose_secret().is_empty() {
            bail!("refusing an empty {prompt}");
        }
        Ok(entered)
    }
}

/// Read one line of secret material, hidden when a terminal is attached.
///
/// A pipe supplies one secret per line, so commands that read several (a
/// Mnemonic and then a Seed Passphrase) each get their own.
pub fn read_secret_line(prompt: &str) -> Result<SecretString> {
    if std::io::stdin().is_terminal() {
        return Ok(SecretString::from(rpassword::prompt_password(format!(
            "{prompt}: "
        ))?));
    }
    let mut raw = String::new();
    if std::io::stdin().lock().read_line(&mut raw)? == 0 {
        bail!("stdin is empty: expected a line holding the {prompt}");
    }
    Ok(trim(raw))
}
