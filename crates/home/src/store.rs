use std::collections::{HashMap, HashSet};
use std::future::ready;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use weft_core::{Address, Grant, Manifest, Pointer, PublicKey, Record, Revoke, verify};

use crate::fail::{Result, fail};
use crate::fs;

pub const EXT: &str = "weft";
pub const RECORDS: &str = "records";
pub const BLOBS: &str = "blobs";

#[derive(Debug, Default)]
struct Cache {
    records: Mutex<HashMap<Address, Arc<Record>>>,
    verified: Mutex<HashMap<(Address, Option<Address>), bool>>,
}

impl Cache {
    fn record(&self, address: Address, path: &Path) -> Result<Option<Arc<Record>>> {
        if let Some(r) = self.records.lock().map_err(|_| "cache poisoned")?.get(&address) {
            return Ok(Some(Arc::clone(r)));
        }
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let Ok(record) = Record::from_bytes(&bytes) else { return Ok(None) };
        if record.address() != address {
            return Ok(None);
        }
        let record = Arc::new(record);
        self.records.lock().map_err(|_| "cache poisoned")?.insert(address, Arc::clone(&record));
        Ok(Some(record))
    }

    fn retain(&self, seen: &HashSet<Address>, manifests: &HashSet<Address>) -> Result<()> {
        self.records.lock().map_err(|_| "cache poisoned")?.retain(|a, _| seen.contains(a));
        self.verified
            .lock()
            .map_err(|_| "cache poisoned")?
            .retain(|(a, m), _| seen.contains(a) && m.is_none_or(|m| manifests.contains(&m)));
        Ok(())
    }

    fn verified(&self, address: Address, record: &Record, manifest: Option<&Manifest>) -> bool {
        let key = (address, manifest.map(|m| Address::of(&m.encode())));
        if let Ok(memo) = self.verified.lock()
            && let Some(known) = memo.get(&key)
        {
            return *known;
        }
        let ok = verify(record, manifest).is_ok();
        if let Ok(mut memo) = self.verified.lock() {
            memo.insert(key, ok);
        }
        ok
    }
}

#[derive(Debug, Clone)]
pub struct Store {
    dir: PathBuf,
    cache: Arc<Cache>,
}

#[derive(Debug)]
pub struct Snapshot {
    entries: Vec<(Address, Arc<Record>)>,
    cache: Arc<Cache>,
}

impl Store {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir, cache: Arc::default() }
    }

    fn record_path(&self, address: &Address) -> PathBuf {
        self.dir.join(RECORDS).join(format!("{address}.{EXT}"))
    }

    pub fn blob_path(&self, address: &Address) -> PathBuf {
        self.dir.join(BLOBS).join(address.to_string())
    }

    pub fn put(&self, record: &Record) -> Result<PathBuf> {
        if record.kind() == weft_core::login::KIND {
            return fail("login records are never stored");
        }
        let path = self.record_path(&record.address());
        fs::write(&path, &record.to_bytes())?;
        Ok(path)
    }

    pub fn keep_blob(&self, address: &Address, data: &[u8]) -> Result<()> {
        let path = self.blob_path(address);
        if path.is_file() {
            return Ok(());
        }
        fs::write(&path, data)
    }

    pub fn record(&self, address: Address) -> Result<Option<Record>> {
        Ok(self.cache.record(address, &self.record_path(&address))?.map(|r| (*r).clone()))
    }

    pub fn blob(&self, address: &Address) -> Result<Option<Vec<u8>>> {
        match std::fs::read(self.blob_path(address)) {
            Ok(data) => Ok(Some(data)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn snapshot(&self) -> Result<Snapshot> {
        let mut entries = Vec::new();
        let dir = self.dir.join(RECORDS);
        if dir.is_dir() {
            for entry in std::fs::read_dir(&dir)? {
                let path = entry?.path();
                if path.extension().and_then(|e| e.to_str()) != Some(EXT) {
                    continue;
                }
                let Some(address) =
                    path.file_stem().and_then(|s| s.to_str()).and_then(|s| s.parse().ok())
                else {
                    continue;
                };
                if let Some(record) = self.cache.record(address, &path)? {
                    entries.push((address, record));
                }
            }
        }
        let seen = entries.iter().map(|(a, _)| *a).collect();
        let manifests = entries
            .iter()
            .filter(|(_, r)| r.kind() == weft_core::manifest::KIND)
            .filter_map(|(_, r)| Manifest::from_record(r).ok())
            .map(|m| Address::of(&m.encode()))
            .collect();
        self.cache.retain(&seen, &manifests)?;
        Ok(Snapshot { entries, cache: Arc::clone(&self.cache) })
    }

    pub fn head<'a>(pointers: &'a [(&'a Record, Pointer)]) -> Option<(&'a Record, &'a Pointer)> {
        Pointer::head(pointers.iter().map(|(r, p)| (*r, p)))
    }
}

impl Snapshot {
    pub fn records(&self) -> impl Iterator<Item = &Record> {
        self.entries.iter().map(|(_, r)| &**r)
    }

    pub fn find(&self, address: Address) -> Option<&Record> {
        self.entries.iter().find(|(a, _)| *a == address).map(|(_, r)| &**r)
    }

    pub fn valid<'a>(&'a self, manifest: Option<&'a Manifest>) -> impl Iterator<Item = &'a Record> {
        self.entries
            .iter()
            .filter(move |(a, r)| self.cache.verified(*a, r, manifest))
            .map(|(_, r)| &**r)
    }

    pub fn own<'a>(
        &'a self,
        author: &PublicKey,
        manifest: Option<&'a Manifest>,
    ) -> impl Iterator<Item = &'a Record> {
        let author = *author;
        self.valid(manifest).filter(move |r| *r.author() == author)
    }

    pub fn manifest_record(&self, author: &PublicKey) -> Option<&Record> {
        self.own(author, None)
            .filter(|r| r.kind() == weft_core::manifest::KIND)
            .filter_map(|r| Manifest::from_record(r).ok().map(|m| (r, m.seq)))
            .max_by_key(|(r, seq)| (*seq, r.created()))
            .map(|(r, _)| r)
    }

    pub fn manifest(&self, author: &PublicKey) -> Option<Manifest> {
        self.manifest_record(author).and_then(|r| Manifest::from_record(r).ok())
    }

    pub fn pointers<'a>(
        &'a self,
        author: &PublicKey,
        name: &str,
        manifest: Option<&'a Manifest>,
    ) -> Vec<(&'a Record, Pointer)> {
        self.own(author, manifest)
            .filter(|r| r.kind() == weft_core::pointer::KIND)
            .filter_map(|r| Pointer::from_record(r).ok().map(|p| (r, p)))
            .filter(|(_, p)| p.name == name)
            .collect()
    }

    pub fn grants<'a>(
        &'a self,
        author: &PublicKey,
        manifest: Option<&'a Manifest>,
        at: u64,
    ) -> Vec<(&'a Record, Grant)> {
        let revoked: Vec<Address> = self
            .own(author, manifest)
            .filter(|r| r.kind() == weft_core::grant::REVOKE)
            .filter_map(|r| Revoke::from_record(r).ok().map(|v| v.grant))
            .collect();
        self.own(author, manifest)
            .filter(|r| r.kind() == weft_core::grant::KIND)
            .filter(|r| !revoked.contains(&r.address()))
            .filter_map(|r| Grant::from_record(r).ok().map(|g| (r, g)))
            .filter(|(_, g)| g.active(at))
            .collect()
    }
}

pub trait Reads: Send + Sync {
    fn record(&self, address: Address) -> impl Future<Output = Result<Option<Record>>> + Send;
    fn manifest(&self, author: PublicKey) -> impl Future<Output = Result<Option<Record>>> + Send;
    fn pointers(
        &self,
        author: PublicKey,
        name: &str,
    ) -> impl Future<Output = Result<Vec<Record>>> + Send;
    fn blob(&self, address: Address) -> impl Future<Output = Result<Option<Vec<u8>>>> + Send;
    fn keep(&self, record: &Record) -> impl Future<Output = Result<()>> + Send;
}

impl Reads for Store {
    fn record(&self, address: Address) -> impl Future<Output = Result<Option<Record>>> + Send {
        ready(Store::record(self, address))
    }

    fn manifest(&self, author: PublicKey) -> impl Future<Output = Result<Option<Record>>> + Send {
        ready(self.snapshot().map(|snap| snap.manifest_record(&author).cloned()))
    }

    fn pointers(
        &self,
        author: PublicKey,
        name: &str,
    ) -> impl Future<Output = Result<Vec<Record>>> + Send {
        ready(self.snapshot().map(|snap| {
            let manifest = snap.manifest(&author);
            snap.pointers(&author, name, manifest.as_ref())
                .into_iter()
                .map(|(r, _)| r.clone())
                .collect()
        }))
    }

    fn blob(&self, address: Address) -> impl Future<Output = Result<Option<Vec<u8>>>> + Send {
        ready(Store::blob(self, &address))
    }

    fn keep(&self, record: &Record) -> impl Future<Output = Result<()>> + Send {
        ready(self.put(record).map(drop))
    }
}

pub fn read_record(path: &Path) -> Result<Record> {
    Ok(Record::from_bytes(&std::fs::read(path)?)?)
}
