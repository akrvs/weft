use std::path::{Path, PathBuf};

use weft_core::{Manifest, Pointer, PublicKey, Record, verify};

use crate::fail::Result;
use crate::fs;

pub const EXT: &str = "weft";

#[derive(Debug)]
pub struct Store {
    dir: PathBuf,
}

impl Store {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    pub fn put(&self, record: &Record) -> Result<PathBuf> {
        let path = self.dir.join(format!("{}.{EXT}", record.address()));
        fs::write(&path, &record.to_bytes())?;
        Ok(path)
    }

    pub fn all(&self) -> Result<Vec<Record>> {
        let mut out = Vec::new();
        if !self.dir.is_dir() {
            return Ok(out);
        }
        for entry in std::fs::read_dir(&self.dir)? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) != Some(EXT) {
                continue;
            }
            if let Ok(record) = Record::from_bytes(&std::fs::read(&path)?) {
                out.push(record);
            }
        }
        Ok(out)
    }

    pub fn manifest(records: &[Record], author: &PublicKey) -> Option<Manifest> {
        records
            .iter()
            .filter(|r| r.author() == author && r.kind() == weft_core::manifest::KIND)
            .filter(|r| verify(r, None).is_ok())
            .filter_map(|r| Manifest::from_record(r).ok().map(|m| (r.created(), m)))
            .max_by_key(|(created, m)| (m.seq, *created))
            .map(|(_, m)| m)
    }

    pub fn pointers<'a>(
        records: &'a [Record],
        author: &PublicKey,
        name: &str,
        manifest: Option<&Manifest>,
    ) -> Vec<(&'a Record, Pointer)> {
        records
            .iter()
            .filter(|r| r.author() == author && r.kind() == weft_core::pointer::KIND)
            .filter(|r| verify(r, manifest).is_ok())
            .filter_map(|r| Pointer::from_record(r).ok().map(|p| (r, p)))
            .filter(|(_, p)| p.name == name)
            .collect()
    }

    pub fn head<'a>(pointers: &'a [(&'a Record, Pointer)]) -> Option<(&'a Record, &'a Pointer)> {
        Pointer::head(pointers.iter().map(|(r, p)| (*r, p)))
    }
}

pub fn read_record(path: &Path) -> Result<Record> {
    Ok(Record::from_bytes(&std::fs::read(path)?)?)
}
