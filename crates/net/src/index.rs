use std::collections::HashSet;
use std::path::Path;

use redb::{Database, ReadableDatabase, ReadableTable, Table, TableDefinition, WriteTransaction};
use weft_core::{Address, Manifest, Pointer, PublicKey, Record};

use crate::Result;

const RECORDS: TableDefinition<&[u8; 32], &[u8]> = TableDefinition::new("records");
const HEADS: TableDefinition<&[u8], &[u8; 32]> = TableDefinition::new("heads");
const MANIFESTS: TableDefinition<&[u8; 32], &[u8; 32]> = TableDefinition::new("manifests");
const PINS: TableDefinition<&[u8; 32], (u64, &[u8; 32])> = TableDefinition::new("pins");
const SPENT: TableDefinition<&[u8; 32], ()> = TableDefinition::new("spent");

#[derive(Debug)]
pub struct Index {
    db: Database,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settlement {
    pub voucher: Address,
    pub until: u64,
    pub author: PublicKey,
    pub pins: Vec<Address>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Swept {
    pub records: Vec<Address>,
    pub blobs: Vec<Address>,
}

fn head_key(author: &PublicKey, name: &str) -> Vec<u8> {
    let mut k = Vec::with_capacity(32usize.saturating_add(name.len()));
    k.extend_from_slice(author.bytes());
    k.extend_from_slice(name.as_bytes());
    k
}

impl Index {
    pub fn open(path: &Path) -> Result<Self> {
        let db = Database::create(path)?;
        let tx = db.begin_write()?;
        tx.open_table(RECORDS)?;
        tx.open_table(HEADS)?;
        tx.open_table(MANIFESTS)?;
        tx.open_table(PINS)?;
        tx.open_table(SPENT)?;
        tx.commit()?;
        Ok(Self { db })
    }

    pub fn get(&self, address: &Address) -> Result<Option<Vec<u8>>> {
        let tx = self.db.begin_read()?;
        let table = tx.open_table(RECORDS)?;
        Ok(table.get(address.bytes())?.map(|v| v.value().to_vec()))
    }

    pub fn record(&self, address: &Address) -> Result<Option<Record>> {
        Ok(self.get(address)?.and_then(|b| Record::from_bytes(&b).ok()))
    }

    pub fn manifest(&self, author: &PublicKey) -> Result<Option<(Record, Manifest)>> {
        let tx = self.db.begin_read()?;
        let table = tx.open_table(MANIFESTS)?;
        let Some(addr) = table.get(author.bytes())?.map(|v| Address::hash(*v.value())) else {
            return Ok(None);
        };
        drop(table);
        drop(tx);
        Ok(self.record(&addr)?.and_then(|r| Manifest::from_record(&r).ok().map(|m| (r, m))))
    }

    pub fn head(&self, author: &PublicKey, name: &str) -> Result<Option<Record>> {
        let tx = self.db.begin_read()?;
        let table = tx.open_table(HEADS)?;
        let Some(addr) =
            table.get(head_key(author, name).as_slice())?.map(|v| Address::hash(*v.value()))
        else {
            return Ok(None);
        };
        drop(table);
        drop(tx);
        self.record(&addr)
    }

    pub fn pin(&self, address: &Address) -> Result<Option<u64>> {
        let tx = self.db.begin_read()?;
        let table = tx.open_table(PINS)?;
        Ok(table.get(address.bytes())?.map(|v| v.value().0))
    }

    pub fn spent(&self, voucher: &Address) -> Result<bool> {
        let tx = self.db.begin_read()?;
        let table = tx.open_table(SPENT)?;
        Ok(table.get(voucher.bytes())?.is_some())
    }

    pub fn put(&self, record: &Record) -> Result<Address> {
        self.commit(&[record], None)?;
        Ok(record.address())
    }

    pub fn commit(&self, records: &[&Record], settlement: Option<&Settlement>) -> Result<()> {
        let tx = self.db.begin_write()?;
        {
            let mut store = tx.open_table(RECORDS)?;
            let mut heads = tx.open_table(HEADS)?;
            let mut manifests = tx.open_table(MANIFESTS)?;
            for record in records {
                insert(&mut store, &mut heads, &mut manifests, record)?;
            }
            if let Some(s) = settlement {
                let mut pins = tx.open_table(PINS)?;
                for address in &s.pins {
                    let current = pins.get(address.bytes())?.map_or(0, |v| v.value().0);
                    pins.insert(address.bytes(), (s.until.max(current), s.author.bytes()))?;
                }
                tx.open_table(SPENT)?.insert(s.voucher.bytes(), ())?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn sweep(&self, now: u64, keep: &HashSet<PublicKey>) -> Result<Swept> {
        let tx = self.db.begin_write()?;
        let swept = sweep(&tx, now, keep)?;
        tx.commit()?;
        Ok(swept)
    }
}

type Records<'a> = Table<'a, &'static [u8; 32], &'static [u8]>;
type Heads<'a> = Table<'a, &'static [u8], &'static [u8; 32]>;
type Manifests<'a> = Table<'a, &'static [u8; 32], &'static [u8; 32]>;

fn stored(table: &Records<'_>, address: &Address) -> Result<Option<Record>> {
    Ok(table.get(address.bytes())?.and_then(|v| Record::from_bytes(v.value()).ok()))
}

fn insert(
    store: &mut Records<'_>,
    heads: &mut Heads<'_>,
    manifests: &mut Manifests<'_>,
    record: &Record,
) -> Result<()> {
    let address = record.address();
    store.insert(address.bytes(), record.to_bytes().as_slice())?;
    if let Ok(m) = Manifest::from_record(record) {
        let current = manifests.get(record.author().bytes())?.map(|v| Address::hash(*v.value()));
        let current_seq = match current {
            Some(a) => {
                stored(store, &a)?.and_then(|r| Manifest::from_record(&r).ok()).map(|m| m.seq)
            }
            None => None,
        };
        if current_seq.is_none_or(|seq| m.seq > seq) {
            manifests.insert(record.author().bytes(), address.bytes())?;
        }
    }
    if let Ok(p) = Pointer::from_record(record) {
        let key = head_key(record.author(), &p.name);
        let current = heads.get(key.as_slice())?.map(|v| Address::hash(*v.value()));
        let current = match current {
            Some(a) => {
                stored(store, &a)?.and_then(|r| Pointer::from_record(&r).ok().map(|q| (r, q)))
            }
            None => None,
        };
        if current.as_ref().is_none_or(|(r, q)| Pointer::compare((record, &p), (r, q)).is_gt()) {
            heads.insert(key.as_slice(), address.bytes())?;
        }
    }
    Ok(())
}

fn sweep(tx: &WriteTransaction, now: u64, keep: &HashSet<PublicKey>) -> Result<Swept> {
    let mut store = tx.open_table(RECORDS)?;
    let mut heads = tx.open_table(HEADS)?;
    let mut manifests = tx.open_table(MANIFESTS)?;
    let mut pins = tx.open_table(PINS)?;
    let mut expired = Vec::new();
    let mut alive: HashSet<[u8; 32]> = HashSet::new();
    for entry in pins.iter()? {
        let (k, v) = entry?;
        let (until, author) = v.value();
        if until < now {
            expired.push(*k.value());
        } else {
            alive.insert(*author);
        }
    }
    let mut swept = Swept::default();
    for address in &expired {
        if let Some(record) = stored(&store, &Address::hash(*address))?
            && let weft_core::Body::Blob(blob) = record.body()
        {
            swept.blobs.push(*blob);
        }
        store.remove(address)?;
        pins.remove(address)?;
        swept.records.push(Address::hash(*address));
    }
    let mut stale_heads = Vec::new();
    for entry in heads.iter()? {
        let (k, v) = entry?;
        if store.get(v.value())?.is_none() {
            stale_heads.push(k.value().to_vec());
        }
    }
    for key in stale_heads {
        heads.remove(key.as_slice())?;
    }
    let mut orphaned = Vec::new();
    for entry in manifests.iter()? {
        let (author, address) = entry?;
        let author = *author.value();
        if !alive.contains(&author) && !keep.iter().any(|k| k.bytes() == &author) {
            orphaned.push((author, *address.value()));
        }
    }
    for (author, address) in orphaned {
        manifests.remove(&author)?;
        store.remove(&address)?;
        swept.records.push(Address::hash(address));
    }
    Ok(swept)
}
