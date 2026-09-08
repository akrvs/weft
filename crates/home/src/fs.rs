use std::fs::{DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;

use crate::fail::Result;

pub fn ensure_dir(path: &Path) -> Result<()> {
    if !path.is_dir() {
        DirBuilder::new().recursive(true).mode(0o700).create(path)?;
    }
    Ok(())
}

pub fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        ensure_dir(parent)?;
    }
    let mut f = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    f.write_all(data)?;
    f.sync_all()?;
    Ok(())
}

pub fn replace_private(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    write_private(&tmp, data)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

pub fn write(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        ensure_dir(parent)?;
    }
    let mut f =
        OpenOptions::new().write(true).create(true).truncate(true).mode(0o644).open(path)?;
    f.write_all(data)?;
    f.sync_all()?;
    Ok(())
}
