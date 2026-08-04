use anyhow::{Context, Result, bail};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// Write through a sibling temporary file so an interrupted write cannot leave
/// a half-written Wallet File where the previous one was.
pub fn write_atomically(path: &Path, bytes: &[u8], allow_overwrite: bool) -> Result<()> {
    if path.exists() && !allow_overwrite {
        bail!(
            "{} already exists (pass --force to replace it)",
            path.display()
        );
    }

    let temp = path.with_extension(format!("tmp.{}", std::process::id()));
    let write = || -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    };

    if let Err(e) = write() {
        let _ = fs::remove_file(&temp);
        return Err(e).with_context(|| format!("writing {}", temp.display()));
    }

    fs::rename(&temp, path).with_context(|| format!("replacing {}", path.display()))
}

pub fn read(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).with_context(|| format!("reading {}", path.display()))
}
