use std::collections::HashSet;
use std::path::Path;

use redb::{
    Database, MultimapTable, MultimapTableDefinition, ReadableDatabase, ReadableMultimapTable,
    ReadableTable, ReadableTableMetadata, Table, TableDefinition, WriteTransaction,
};
use weft_core::{Address, Body, Manifest, Pointer, PublicKey, Record, Recovery};

use crate::{Error, Result};

const RECORDS: TableDefinition<&[u8; 32], &[u8]> = TableDefinition::new("records");
const HEADS: TableDefinition<&[u8], &[u8; 32]> = TableDefinition::new("heads");
const MANIFESTS: TableDefinition<&[u8; 32], &[u8; 32]> = TableDefinition::new("manifests");
const RECOVERIES: TableDefinition<&[u8; 32], &[u8; 32]> = TableDefinition::new("recoveries");
const PINS: TableDefinition<&[u8; 32], (u64, &[u8; 32])> = TableDefinition::new("pins");
const SPENT: TableDefinition<&[u8; 32], ()> = TableDefinition::new("spent");
const INVOICES: TableDefinition<&[u8; 32], (u64, u64)> = TableDefinition::new("invoices");
const AUTHORS: MultimapTableDefinition<&[u8; 32], &[u8; 32]> =
    MultimapTableDefinition::new("authors");
const BLOBS: TableDefinition<&[u8; 32], &[u8; 32]> = TableDefinition::new("blobs");

pub const MAX_INVOICES: u64 = 4096;

#[derive(Debug)]
pub struct Index {
    db: Database,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settlement {
    pub payment: Address,
    pub invoice: Option<[u8; 32]>,
    pub until: u64,
    pub author: PublicKey,
    pub pins: Vec<Address>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Swept {
    pub records: Vec<Address>,
}

fn head_key(author: &PublicKey, name: &str) -> Vec<u8> {
    let mut k = Vec::with_capacity(32usize.saturating_add(name.len()));
    k.extend_from_slice(author.bytes());
    k.extend_from_slice(name.as_bytes());
    k
}

fn after(author: &[u8; 32]) -> Option<[u8; 32]> {
    let mut next = *author;
    for byte in next.iter_mut().rev() {
        if *byte == u8::MAX {
            *byte = 0;
        } else {
            *byte = byte.saturating_add(1);
            return Some(next);
        }
    }
    None
}

impl Index {
    pub fn open(path: &Path) -> Result<Self> {
        let db = Database::create(path)?;
        let tx = db.begin_write()?;
        {
            let store = tx.open_table(RECORDS)?;
            tx.open_table(HEADS)?;
            tx.open_table(MANIFESTS)?;
            tx.open_table(RECOVERIES)?;
            tx.open_table(PINS)?;
            tx.open_table(SPENT)?;
            tx.open_table(INVOICES)?;
            let mut authors = tx.open_multimap_table(AUTHORS)?;
            let mut blobs = tx.open_table(BLOBS)?;
            if authors.is_empty()? && !store.is_empty()? {
                for entry in store.iter()? {
                    let (k, v) = entry?;
                    if let Ok(record) = Record::from_bytes(v.value()) {
                        index(&mut authors, &mut blobs, k.value(), &record)?;
                    }
                }
            }
        }
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

    pub fn recovery(&self, author: &PublicKey) -> Result<Option<Record>> {
        let tx = self.db.begin_read()?;
        let table = tx.open_table(RECOVERIES)?;
        let Some(addr) = table.get(author.bytes())?.map(|v| Address::hash(*v.value())) else {
            return Ok(None);
        };
        drop(table);
        drop(tx);
        self.record(&addr)
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

    pub fn spent(&self, payment: &Address) -> Result<bool> {
        let tx = self.db.begin_read()?;
        let table = tx.open_table(SPENT)?;
        Ok(table.get(payment.bytes())?.is_some())
    }

    pub fn open_invoices(&self) -> Result<u64> {
        let tx = self.db.begin_read()?;
        Ok(tx.open_table(INVOICES)?.len()?)
    }

    pub fn issue(&self, hash: &[u8; 32], cents: u64, expires: u64, cap: u64) -> Result<()> {
        let tx = self.db.begin_write()?;
        {
            let mut table = tx.open_table(INVOICES)?;
            if table.len()? >= cap {
                return Err(Error::Refused("too many open invoices".to_owned()));
            }
            table.insert(hash, (cents, expires))?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn invoice(&self, hash: &[u8; 32]) -> Result<Option<(u64, u64)>> {
        let tx = self.db.begin_read()?;
        let table = tx.open_table(INVOICES)?;
        Ok(table.get(hash)?.map(|v| v.value()))
    }

    pub fn put(&self, record: &Record) -> Result<Address> {
        self.commit(&[record], None)?;
        Ok(record.address())
    }

    pub fn commit(&self, records: &[&Record], settlement: Option<&Settlement>) -> Result<()> {
        let tx = self.db.begin_write()?;
        {
            let mut tables = Tables::open(&tx)?;
            for record in records {
                tables.insert(record)?;
            }
            if let Some(s) = settlement {
                let mut pins = tx.open_table(PINS)?;
                for address in &s.pins {
                    let current = pins.get(address.bytes())?.map_or(0, |v| v.value().0);
                    pins.insert(address.bytes(), (s.until.max(current), s.author.bytes()))?;
                }
                tx.open_table(SPENT)?.insert(s.payment.bytes(), ())?;
                if let Some(hash) = &s.invoice {
                    tx.open_table(INVOICES)?.remove(hash)?;
                }
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn blobs(&self) -> Result<HashSet<[u8; 32]>> {
        let tx = self.db.begin_read()?;
        let table = tx.open_table(BLOBS)?;
        let mut blobs = HashSet::new();
        for entry in table.iter()? {
            let (_, v) = entry?;
            blobs.insert(*v.value());
        }
        Ok(blobs)
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
type Authors<'a> = MultimapTable<'a, &'static [u8; 32], &'static [u8; 32]>;
type Blobs<'a> = Table<'a, &'static [u8; 32], &'static [u8; 32]>;

struct Tables<'a> {
    store: Records<'a>,
    heads: Heads<'a>,
    manifests: Manifests<'a>,
    recoveries: Manifests<'a>,
    authors: Authors<'a>,
    blobs: Blobs<'a>,
}

fn stored(table: &Records<'_>, address: &Address) -> Result<Option<Record>> {
    Ok(table.get(address.bytes())?.and_then(|v| Record::from_bytes(v.value()).ok()))
}

fn index(
    authors: &mut Authors<'_>,
    blobs: &mut Blobs<'_>,
    address: &[u8; 32],
    record: &Record,
) -> Result<()> {
    authors.insert(record.author().bytes(), address)?;
    if let Body::Blob(blob) = record.body() {
        blobs.insert(address, blob.bytes())?;
    }
    Ok(())
}

impl<'a> Tables<'a> {
    fn open(tx: &'a WriteTransaction) -> Result<Self> {
        Ok(Self {
            store: tx.open_table(RECORDS)?,
            heads: tx.open_table(HEADS)?,
            manifests: tx.open_table(MANIFESTS)?,
            recoveries: tx.open_table(RECOVERIES)?,
            authors: tx.open_multimap_table(AUTHORS)?,
            blobs: tx.open_table(BLOBS)?,
        })
    }

    fn insert(&mut self, record: &Record) -> Result<()> {
        let address = record.address();
        self.store.insert(address.bytes(), record.to_bytes().as_slice())?;
        index(&mut self.authors, &mut self.blobs, address.bytes(), record)?;
        if let Ok(m) = Manifest::from_record(record) {
            let current =
                self.manifests.get(record.author().bytes())?.map(|v| Address::hash(*v.value()));
            let current_seq = match current {
                Some(a) => stored(&self.store, &a)?
                    .and_then(|r| Manifest::from_record(&r).ok())
                    .map(|m| m.seq),
                None => None,
            };
            if current_seq.is_none_or(|seq| m.seq > seq) {
                self.manifests.insert(record.author().bytes(), address.bytes())?;
            }
        }
        if let Ok(p) = Pointer::from_record(record) {
            let key = head_key(record.author(), &p.name);
            let current = self.heads.get(key.as_slice())?.map(|v| Address::hash(*v.value()));
            let current = match current {
                Some(a) => stored(&self.store, &a)?
                    .and_then(|r| Pointer::from_record(&r).ok().map(|q| (r, q))),
                None => None,
            };
            if current.as_ref().is_none_or(|(r, q)| Pointer::compare((record, &p), (r, q)).is_gt())
            {
                self.heads.insert(key.as_slice(), address.bytes())?;
            }
        }
        if let Ok(v) = Recovery::from_record(record) {
            let current =
                self.recoveries.get(record.author().bytes())?.map(|v| Address::hash(*v.value()));
            let current = match current {
                Some(a) => stored(&self.store, &a)?
                    .and_then(|r| Recovery::from_record(&r).ok().map(|w| (r, w))),
                None => None,
            };
            if current.as_ref().is_none_or(|(r, w)| Recovery::compare((record, &v), (r, w)).is_gt())
            {
                self.recoveries.insert(record.author().bytes(), address.bytes())?;
            }
        }
        Ok(())
    }

    fn remove(&mut self, author: &[u8; 32], dropped: &HashSet<[u8; 32]>) -> Result<()> {
        for address in dropped {
            self.store.remove(address)?;
            self.authors.remove(author, address)?;
            self.blobs.remove(address)?;
        }
        if self.manifests.get(author)?.is_some_and(|m| dropped.contains(m.value())) {
            self.manifests.remove(author)?;
        }
        if self.recoveries.get(author)?.is_some_and(|m| dropped.contains(m.value())) {
            self.recoveries.remove(author)?;
        }
        let lower: &[u8] = author;
        let upper = after(author);
        let stays = |_: &[u8], v: &[u8; 32]| !dropped.contains(v);
        match upper.as_ref() {
            Some(upper) => self.heads.retain_in(lower..upper.as_slice(), stays)?,
            None => self.heads.retain_in(lower.., stays)?,
        }
        Ok(())
    }
}

fn sweep(tx: &WriteTransaction, now: u64, keep: &HashSet<PublicKey>) -> Result<Swept> {
    let mut tables = Tables::open(tx)?;
    tx.open_table(INVOICES)?.retain(|_, (_, expires)| expires >= now)?;
    let mut pins = tx.open_table(PINS)?;
    let keep: HashSet<&[u8; 32]> = keep.iter().map(PublicKey::bytes).collect();
    let mut expired = Vec::new();
    let mut pinned: HashSet<[u8; 32]> = HashSet::new();
    for entry in pins.iter()? {
        let (k, v) = entry?;
        if v.value().0 < now {
            expired.push(*k.value());
        } else {
            pinned.insert(*k.value());
        }
    }
    for address in &expired {
        pins.remove(address)?;
    }
    let mut dropped: Vec<([u8; 32], HashSet<[u8; 32]>)> = Vec::new();
    for entry in tables.authors.iter()? {
        let (author, records) = entry?;
        let author = *author.value();
        if keep.contains(&author) {
            continue;
        }
        let records = records
            .map(|r| r.map(|v| *v.value()).map_err(crate::Error::from))
            .collect::<Result<Vec<_>>>()?;
        let manifest = if records.iter().any(|a| pinned.contains(a)) {
            tables.manifests.get(&author)?.map(|m| *m.value())
        } else {
            None
        };
        let gone: HashSet<[u8; 32]> =
            records.into_iter().filter(|a| !pinned.contains(a) && manifest != Some(*a)).collect();
        if !gone.is_empty() {
            dropped.push((author, gone));
        }
    }
    let mut swept = Swept::default();
    for (author, gone) in &dropped {
        tables.remove(author, gone)?;
        swept.records.extend(gone.iter().map(|a| Address::hash(*a)));
    }
    swept.records.sort();
    Ok(swept)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use weft_core::{Draft, SecretKey};

    fn record(n: u8, body: Body) -> Record {
        let key = SecretKey::from_seed([n; 32]);
        Draft {
            author: key.public(),
            signer: key.public(),
            kind: "page".into(),
            created: 1_700_000_000,
            refs: vec![],
            body,
        }
        .sign(&key)
        .unwrap()
    }

    #[test]
    fn an_index_without_derived_tables_rebuilds_them_at_open() {
        let dir = std::env::temp_dir().join(format!("weft-index-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("index.redb");
        let page = record(1, Body::Inline(b"# Page".to_vec()));
        let blob = Address::hash([7; 32]);
        let named = record(2, Body::Blob(blob));
        {
            let db = Database::create(&path).unwrap();
            let tx = db.begin_write().unwrap();
            {
                let mut store = tx.open_table(RECORDS).unwrap();
                for r in [&page, &named] {
                    store.insert(r.address().bytes(), r.to_bytes().as_slice()).unwrap();
                }
            }
            tx.commit().unwrap();
        }
        let index = Index::open(&path).unwrap();
        assert_eq!(index.blobs().unwrap(), [*blob.bytes()].into_iter().collect());
        let keep = [*page.author()].into_iter().collect();
        let swept = index.sweep(1_700_000_001, &keep).unwrap();
        assert_eq!(swept.records, vec![named.address()]);
        assert!(index.blobs().unwrap().is_empty(), "a swept record leaves the blobs table");
        assert!(index.record(&page.address()).unwrap().is_some());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn open_invoices_are_capped_settled_once_and_swept_at_expiry() {
        let dir = std::env::temp_dir().join(format!("weft-invoices-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let index = Index::open(&dir.join("index.redb")).unwrap();
        index.issue(&[1; 32], 5, 200, 2).unwrap();
        index.issue(&[2; 32], 6, 100, 2).unwrap();
        let full = index.issue(&[3; 32], 7, 300, 2).unwrap_err();
        assert!(full.to_string().contains("too many open invoices"), "{full}");
        assert_eq!(index.open_invoices().unwrap(), 2);
        assert_eq!(index.invoice(&[1; 32]).unwrap(), Some((5, 200)));
        let paid = Address::hash([9; 32]);
        let settlement = Settlement {
            payment: paid,
            invoice: Some([1; 32]),
            until: 500,
            author: SecretKey::from_seed([4; 32]).public(),
            pins: vec![],
        };
        index.commit(&[], Some(&settlement)).unwrap();
        assert!(index.spent(&paid).unwrap());
        assert_eq!(index.invoice(&[1; 32]).unwrap(), None);
        index.sweep(150, &HashSet::new()).unwrap();
        assert_eq!(index.invoice(&[2; 32]).unwrap(), None, "expired invoices are swept");
        assert_eq!(index.open_invoices().unwrap(), 0);
        index.issue(&[3; 32], 7, 300, 2).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
