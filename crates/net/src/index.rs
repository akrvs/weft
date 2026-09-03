use std::path::Path;

use redb::{Database, ReadableDatabase, TableDefinition};
use weft_core::{Address, Manifest, Pointer, PublicKey, Record};

use crate::Result;

const RECORDS: TableDefinition<&[u8; 32], &[u8]> = TableDefinition::new("records");
const HEADS: TableDefinition<&[u8], &[u8; 32]> = TableDefinition::new("heads");
const MANIFESTS: TableDefinition<&[u8; 32], &[u8; 32]> = TableDefinition::new("manifests");

#[derive(Debug)]
pub struct Index {
    db: Database,
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
        tx.commit()?;
        Ok(Self { db })
    }

    pub fn get(&self, address: &Address) -> Result<Option<Vec<u8>>> {
        let tx = self.db.begin_read()?;
        let table = tx.open_table(RECORDS)?;
        Ok(table.get(address.bytes())?.map(|v| v.value().to_vec()))
    }

    fn record(&self, address: &Address) -> Result<Option<Record>> {
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

    pub fn put(&self, record: &Record) -> Result<Address> {
        let address = record.address();
        let bytes = record.to_bytes();
        let manifest = Manifest::from_record(record).ok();
        let pointer = Pointer::from_record(record).ok();
        let current_manifest = self.manifest(record.author())?.map(|(_, m)| m.seq);
        let current_head = match &pointer {
            Some(p) => self
                .head(record.author(), &p.name)?
                .and_then(|r| Pointer::from_record(&r).ok().map(|q| (r, q))),
            None => None,
        };
        let tx = self.db.begin_write()?;
        {
            let mut records = tx.open_table(RECORDS)?;
            records.insert(address.bytes(), bytes.as_slice())?;
            if let Some(m) = manifest
                && current_manifest.is_none_or(|seq| m.seq > seq)
            {
                let mut manifests = tx.open_table(MANIFESTS)?;
                manifests.insert(record.author().bytes(), address.bytes())?;
            }
            if let Some(p) = pointer {
                let newer = current_head
                    .as_ref()
                    .is_none_or(|(r, q)| Pointer::compare((record, &p), (r, q)).is_gt());
                if newer {
                    let mut heads = tx.open_table(HEADS)?;
                    heads.insert(head_key(record.author(), &p.name).as_slice(), address.bytes())?;
                }
            }
        }
        tx.commit()?;
        Ok(address)
    }
}
