use std::borrow::Borrow;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::future::ready;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use weft_core::{Address, Grant, Manifest, Pointer, PublicKey, Record, Revoke, verify};

use crate::fail::{Result, fail};
use crate::fs;

pub const EXT: &str = "weft";
pub const RECORDS: &str = "records";
pub const BLOBS: &str = "blobs";
pub const PART: &str = "part";
pub const PART_TTL: Duration = Duration::from_secs(120);

pub const DEFAULT_CACHE: u64 = 256 * 1024 * 1024;
const SETTLE: Duration = Duration::from_secs(1);

#[derive(Debug)]
struct Entry {
    record: Arc<Record>,
    size: u64,
    tick: u64,
}

#[derive(Debug)]
struct Lru {
    cap: u64,
    total: u64,
    tick: u64,
    entries: HashMap<Address, Entry>,
    order: BTreeMap<u64, Address>,
}

impl Lru {
    fn new(cap: u64) -> Self {
        Self { cap, total: 0, tick: 0, entries: HashMap::new(), order: BTreeMap::new() }
    }

    fn get(&mut self, address: Address) -> Option<Arc<Record>> {
        let entry = self.entries.get_mut(&address)?;
        self.order.remove(&entry.tick);
        self.tick += 1;
        entry.tick = self.tick;
        self.order.insert(self.tick, address);
        Some(Arc::clone(&entry.record))
    }

    fn insert(&mut self, address: Address, record: Arc<Record>, size: u64) {
        self.remove(address);
        self.tick += 1;
        self.order.insert(self.tick, address);
        self.entries.insert(address, Entry { record, size, tick: self.tick });
        self.total += size;
        while self.cap > 0 && self.total > self.cap {
            let Some((_, oldest)) = self.order.pop_first() else { break };
            if let Some(gone) = self.entries.remove(&oldest) {
                self.total -= gone.size;
            }
        }
    }

    fn remove(&mut self, address: Address) {
        if let Some(gone) = self.entries.remove(&address) {
            self.order.remove(&gone.tick);
            self.total -= gone.size;
        }
    }

    fn retain(&mut self, seen: &HashSet<Address>) {
        let gone: Vec<Address> =
            self.entries.keys().filter(|a| !seen.contains(a)).copied().collect();
        for address in gone {
            self.remove(address);
        }
    }
}

#[derive(Debug)]
struct Meta {
    address: Address,
    author: PublicKey,
    kind: Box<str>,
    name: Option<Box<str>>,
}

impl Meta {
    fn of(address: Address, record: &Record) -> Self {
        let name = (record.kind() == weft_core::pointer::KIND)
            .then(|| Pointer::from_record(record).ok().map(|p| p.name.into_boxed_str()))
            .flatten();
        Self { address, author: *record.author(), kind: record.kind().into(), name }
    }
}

#[derive(Debug)]
struct Index {
    metas: Vec<Meta>,
    positions: HashMap<Address, usize>,
    mtime: Option<SystemTime>,
    trusted: bool,
}

#[derive(Debug)]
struct Cache {
    records: Mutex<Lru>,
    verified: Mutex<HashMap<(Address, Option<Address>), bool>>,
    index: Mutex<Option<Arc<Index>>>,
}

impl Cache {
    fn new(cap: u64) -> Self {
        Self {
            records: Mutex::new(Lru::new(cap)),
            verified: Mutex::default(),
            index: Mutex::default(),
        }
    }

    fn record(&self, address: Address, path: &Path) -> Result<Option<Arc<Record>>> {
        if let Some(r) = self.records.lock().map_err(|_| "cache poisoned")?.get(address) {
            return Ok(Some(r));
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
        self.records.lock().map_err(|_| "cache poisoned")?.insert(
            address,
            Arc::clone(&record),
            bytes.len() as u64,
        );
        Ok(Some(record))
    }

    fn bytes(&self) -> u64 {
        self.records.lock().map_or(0, |l| l.total)
    }

    fn retain(&self, seen: &HashSet<Address>, manifests: &HashSet<Address>) -> Result<()> {
        self.records.lock().map_err(|_| "cache poisoned")?.retain(seen);
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
    index: Arc<Index>,
    dir: PathBuf,
    cache: Arc<Cache>,
}

impl Store {
    pub fn new(dir: PathBuf) -> Self {
        Self::with_cache(dir, DEFAULT_CACHE)
    }

    pub fn with_cache(dir: PathBuf, bytes: u64) -> Self {
        Self { dir, cache: Arc::new(Cache::new(bytes)) }
    }

    pub fn cached_bytes(&self) -> u64 {
        self.cache.bytes()
    }

    fn record_path(&self, address: &Address) -> PathBuf {
        self.dir.join(RECORDS).join(format!("{address}.{EXT}"))
    }

    pub fn blob_path(&self, address: &Address) -> PathBuf {
        self.dir.join(BLOBS).join(address.to_string())
    }

    pub fn part_path(&self, address: &Address) -> PathBuf {
        self.blob_path(address).with_extension(PART)
    }

    pub fn sweep_parts(&self, older_than: Option<Duration>) -> Result<usize> {
        let dir = self.dir.join(BLOBS);
        if !dir.is_dir() {
            return Ok(0);
        }
        let now = SystemTime::now();
        let mut swept = 0;
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some(PART) {
                continue;
            }
            let stale = match older_than {
                None => true,
                Some(age) => {
                    let modified = entry.metadata()?.modified()?;
                    now.duration_since(modified).is_ok_and(|since| since > age)
                }
            };
            if stale {
                std::fs::remove_file(&path)?;
                swept += 1;
            }
        }
        Ok(swept)
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
        if Address::of(data) != *address {
            return fail("blob does not hash to its address");
        }
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
        self.sweep_parts(Some(PART_TTL))?;
        let dir = self.dir.join(RECORDS);
        let mtime = match std::fs::metadata(&dir) {
            Ok(m) => Some(m.modified()?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        let current = self.cache.index.lock().map_err(|_| "cache poisoned")?.clone();
        let index = match current {
            Some(i) if i.trusted && i.mtime == mtime => i,
            _ => {
                let index = Arc::new(self.walk(&dir, mtime)?);
                *self.cache.index.lock().map_err(|_| "cache poisoned")? = Some(Arc::clone(&index));
                index
            }
        };
        Ok(Snapshot { index, dir: self.dir.clone(), cache: Arc::clone(&self.cache) })
    }

    fn walk(&self, dir: &Path, mtime: Option<SystemTime>) -> Result<Index> {
        let trusted = mtime
            .is_some_and(|m| SystemTime::now().duration_since(m).is_ok_and(|age| age >= SETTLE));
        let mut metas = Vec::new();
        let mut manifests = HashSet::new();
        if mtime.is_some() {
            for entry in std::fs::read_dir(dir)? {
                let path = entry?.path();
                if path.extension().and_then(|e| e.to_str()) != Some(EXT) {
                    continue;
                }
                let Some(address) =
                    path.file_stem().and_then(|s| s.to_str()).and_then(|s| s.parse().ok())
                else {
                    continue;
                };
                let Some(record) = self.cache.record(address, &path)? else { continue };
                if record.kind() == weft_core::manifest::KIND
                    && let Ok(m) = Manifest::from_record(&record)
                {
                    manifests.insert(Address::of(&m.encode()));
                }
                metas.push(Meta::of(address, &record));
            }
        }
        let positions = metas.iter().enumerate().map(|(i, m)| (m.address, i)).collect();
        let seen = metas.iter().map(|m| m.address).collect();
        self.cache.retain(&seen, &manifests)?;
        Ok(Index { metas, positions, mtime, trusted })
    }

    pub fn head<R: Borrow<Record>>(pointers: &[(R, Pointer)]) -> Option<(&Record, &Pointer)> {
        Pointer::head(pointers.iter().map(|(r, p)| (r.borrow(), p)))
    }
}

impl Snapshot {
    pub fn len(&self) -> usize {
        self.index.metas.len()
    }

    pub fn is_empty(&self) -> bool {
        self.index.metas.is_empty()
    }

    fn load(&self, meta: &Meta) -> Option<Arc<Record>> {
        let path = self.dir.join(RECORDS).join(format!("{}.{EXT}", meta.address));
        self.cache.record(meta.address, &path).ok().flatten()
    }

    fn valid<'a>(
        &'a self,
        metas: impl Iterator<Item = &'a Meta> + 'a,
        manifest: Option<&'a Manifest>,
    ) -> impl Iterator<Item = Arc<Record>> + 'a {
        metas
            .filter_map(move |m| self.load(m).map(|r| (m.address, r)))
            .filter(move |(a, r)| self.cache.verified(*a, r, manifest))
            .map(|(_, r)| r)
    }

    fn by<'a>(&'a self, author: &PublicKey, kind: &'a str) -> impl Iterator<Item = &'a Meta> + 'a {
        let author = *author;
        self.index.metas.iter().filter(move |m| m.author == author && &*m.kind == kind)
    }

    pub fn records(&self) -> impl Iterator<Item = Arc<Record>> + '_ {
        self.index.metas.iter().filter_map(|m| self.load(m))
    }

    pub fn find(&self, address: Address) -> Option<Arc<Record>> {
        let i = *self.index.positions.get(&address)?;
        self.load(self.index.metas.get(i)?)
    }

    pub fn verified(&self, address: Address) -> Option<Arc<Record>> {
        let record = self.find(address)?;
        let manifest = self.manifest(record.author());
        self.cache.verified(address, &record, manifest.as_ref()).then_some(record)
    }

    pub fn own<'a>(
        &'a self,
        author: &PublicKey,
        manifest: Option<&'a Manifest>,
    ) -> impl Iterator<Item = Arc<Record>> + 'a {
        let author = *author;
        self.valid(self.index.metas.iter().filter(move |m| m.author == author), manifest)
    }

    pub fn readable<'a>(&'a self, kind: &'a str) -> impl Iterator<Item = Arc<Record>> + 'a {
        let mut manifests: HashMap<PublicKey, Option<Manifest>> = HashMap::new();
        self.index.metas.iter().filter(move |m| &*m.kind == kind).filter_map(move |m| {
            let manifest = manifests.entry(m.author).or_insert_with(|| self.manifest(&m.author));
            let record = self.load(m)?;
            self.cache.verified(m.address, &record, manifest.as_ref()).then_some(record)
        })
    }

    pub fn manifest_record(&self, author: &PublicKey) -> Option<Arc<Record>> {
        self.valid(self.by(author, weft_core::manifest::KIND), None)
            .filter_map(|r| Manifest::from_record(&r).ok().map(|m| (r, m.seq)))
            .max_by_key(|(r, seq)| (*seq, r.created()))
            .map(|(r, _)| r)
    }

    pub fn manifest(&self, author: &PublicKey) -> Option<Manifest> {
        self.manifest_record(author).and_then(|r| Manifest::from_record(&r).ok())
    }

    pub fn pointers<'a>(
        &'a self,
        author: &PublicKey,
        name: &str,
        manifest: Option<&'a Manifest>,
    ) -> Vec<(Arc<Record>, Pointer)> {
        let metas =
            self.by(author, weft_core::pointer::KIND).filter(|m| m.name.as_deref() == Some(name));
        self.valid(metas, manifest)
            .filter_map(|r| Pointer::from_record(&r).ok().map(|p| (r, p)))
            .collect()
    }

    pub fn grants<'a>(
        &'a self,
        author: &PublicKey,
        manifest: Option<&'a Manifest>,
        at: u64,
    ) -> Vec<(Arc<Record>, Grant)> {
        let revoked: Vec<Address> = self
            .valid(self.by(author, weft_core::grant::REVOKE), manifest)
            .filter_map(|r| Revoke::from_record(&r).ok().map(|v| v.grant))
            .collect();
        self.valid(self.by(author, weft_core::grant::KIND), manifest)
            .filter(|r| !revoked.contains(&r.address()))
            .filter_map(|r| Grant::from_record(&r).ok().map(|g| (r, g)))
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
    fn keep_blob(&self, address: Address, data: &[u8]) -> impl Future<Output = Result<()>> + Send;
}

impl Reads for Store {
    fn record(&self, address: Address) -> impl Future<Output = Result<Option<Record>>> + Send {
        ready(Store::record(self, address))
    }

    fn manifest(&self, author: PublicKey) -> impl Future<Output = Result<Option<Record>>> + Send {
        ready(self.snapshot().map(|snap| snap.manifest_record(&author).map(|r| (*r).clone())))
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
                .map(|(r, _)| (*r).clone())
                .collect()
        }))
    }

    fn blob(&self, address: Address) -> impl Future<Output = Result<Option<Vec<u8>>>> + Send {
        ready(Store::blob(self, &address))
    }

    fn keep(&self, record: &Record) -> impl Future<Output = Result<()>> + Send {
        ready(self.put(record).map(drop))
    }

    fn keep_blob(&self, address: Address, data: &[u8]) -> impl Future<Output = Result<()>> + Send {
        ready(Store::keep_blob(self, &address, data))
    }
}

pub fn read_record(path: &Path) -> Result<Record> {
    Ok(Record::from_bytes(&std::fs::read(path)?)?)
}
