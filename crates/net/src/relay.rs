use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::{Endpoint, EndpointId};
use iroh_blobs::api::blobs::BlobStatus;
use iroh_blobs::store::fs::FsStore;
use iroh_blobs::{BlobsProtocol, Hash};
use weft_core::{Address, Body, Manifest, PublicKey, Receipt, Record, receipt, verify};

use crate::error::net;
use crate::index::{Index, Settlement, Swept};
use crate::wire::{self, Request, Response};
use crate::{Error, Result};

pub const MAX_DAYS: u64 = 366;
const DAY: u64 = 86_400;
const KIB: u64 = 1024;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Pricing {
    pub rate: u64,
    pub banks: HashSet<PublicKey>,
}

#[derive(Debug, Clone)]
pub struct Relay {
    index: Arc<Index>,
    blobs: FsStore,
    allow: Arc<HashSet<PublicKey>>,
    pricing: Arc<Pricing>,
    endpoint: Endpoint,
}

struct Pending {
    index: u64,
    record: Record,
    size: u64,
}

struct Batch {
    stored: Vec<Address>,
    rejected: Vec<(u64, String)>,
    pending: Vec<Pending>,
    manifests: HashMap<PublicKey, Manifest>,
}

pub fn now() -> u64 {
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

pub fn cost(size: u64, days: u64, rate: u64) -> Option<u64> {
    size.div_ceil(KIB).checked_mul(days)?.checked_mul(rate)
}

impl Relay {
    pub async fn open(
        endpoint: Endpoint,
        dir: &Path,
        allow: HashSet<PublicKey>,
        pricing: Pricing,
    ) -> Result<Self> {
        std::fs::create_dir_all(dir).map_err(|e| Error::Store(e.to_string()))?;
        let index = Arc::new(Index::open(&dir.join("index.redb"))?);
        let blobs =
            FsStore::load(dir.join("blobs")).await.map_err(|e| Error::Store(e.to_string()))?;
        Ok(Self { index, blobs, allow: Arc::new(allow), pricing: Arc::new(pricing), endpoint })
    }

    pub fn spawn(self) -> Router {
        let blobs = BlobsProtocol::new(&self.blobs, None);
        Router::builder(self.endpoint.clone())
            .accept(wire::ALPN, self)
            .accept(iroh_blobs::ALPN, blobs)
            .spawn()
    }

    pub fn id(&self) -> EndpointId {
        self.endpoint.id()
    }

    pub fn key(&self) -> Result<PublicKey> {
        PublicKey::from_bytes(self.endpoint.id().as_bytes()).map_err(Error::Core)
    }

    pub fn sweep(&self, now: u64) -> Result<Swept> {
        self.index.sweep(now, &self.allow)
    }

    pub fn sweeper(&self, every: Duration) -> tokio::task::JoinHandle<()> {
        let relay = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(every);
            loop {
                tick.tick().await;
                let _ = relay.sweep(now());
            }
        })
    }

    async fn handle(&self, request: Request, from: EndpointId) -> Response {
        match request {
            Request::Put { records } => self.put(records, from).await,
            Request::Get { address } => match self.index.get(&address) {
                Ok(record) => Response::Get { record },
                Err(e) => Response::Error { why: e.to_string() },
            },
            Request::Head { author, name } => {
                let pointer = self.index.head(&author, &name).map(|r| r.map(|r| r.to_bytes()));
                let manifest = self.index.manifest(&author).map(|m| m.map(|(r, _)| r.to_bytes()));
                match (pointer, manifest) {
                    (Ok(pointer), Ok(manifest)) => Response::Head { pointer, manifest },
                    (Err(e), _) | (_, Err(e)) => Response::Error { why: e.to_string() },
                }
            }
            Request::Price => {
                let mut banks: Vec<_> = self.pricing.banks.iter().copied().collect();
                banks.sort();
                Response::Price { rate: self.pricing.rate, banks }
            }
        }
    }

    async fn put(&self, records: Vec<Vec<u8>>, from: EndpointId) -> Response {
        let mut batch = Batch {
            stored: Vec::new(),
            rejected: Vec::new(),
            pending: Vec::new(),
            manifests: HashMap::new(),
        };
        let mut parsed: Vec<(u64, Record)> = Vec::with_capacity(records.len());
        for (i, bytes) in (0u64..).zip(&records) {
            match Record::from_bytes(bytes) {
                Ok(r) => parsed.push((i, r)),
                Err(e) => batch.rejected.push((i, e.to_string())),
            }
        }
        parsed.sort_by_key(|(_, r)| {
            (r.kind() != weft_core::manifest::KIND, r.kind() == receipt::KIND)
        });
        for (i, record) in parsed {
            let outcome = if record.kind() == receipt::KIND {
                self.settle(&record, from, &mut batch).await
            } else {
                self.store(i, record, from, &mut batch).await
            };
            if let Err(e) = outcome {
                batch.rejected.push((i, e.to_string()));
            }
        }
        for p in batch.pending {
            batch.rejected.push((p.index, "payment required".to_owned()));
        }
        batch.rejected.sort_unstable_by_key(|(i, _)| *i);
        Response::Put { stored: batch.stored, rejected: batch.rejected }
    }

    async fn prepare(
        &self,
        record: &Record,
        from: EndpointId,
        manifests: &HashMap<PublicKey, Manifest>,
    ) -> Result<u64> {
        let manifest: Option<Manifest> = if record.self_signed() {
            None
        } else {
            match manifests.get(record.author()) {
                Some(m) => Some(m.clone()),
                None => self.index.manifest(record.author())?.map(|(_, m)| m),
            }
        };
        verify(record, manifest.as_ref())?;
        let mut size = record.to_bytes().len() as u64;
        if let Body::Blob(address) = record.body() {
            let hash = Hash::from_bytes(*address.bytes());
            let present = self.blobs.blobs().has(hash).await.map_err(net)?;
            if !present {
                self.blobs
                    .downloader(&self.endpoint)
                    .download(hash, Some(from))
                    .await
                    .map_err(net)?;
            }
            size = size.saturating_add(self.blob_size(address).await?);
        }
        Ok(size)
    }

    async fn blob_size(&self, address: &Address) -> Result<u64> {
        let hash = Hash::from_bytes(*address.bytes());
        match self.blobs.blobs().status(hash).await.map_err(net)? {
            BlobStatus::Complete { size } => Ok(size),
            _ => Err(Error::Store("blob incomplete".to_owned())),
        }
    }

    async fn store(
        &self,
        index: u64,
        record: Record,
        from: EndpointId,
        batch: &mut Batch,
    ) -> Result<()> {
        let size = self.prepare(&record, from, &batch.manifests).await?;
        if self.allow.contains(record.author()) {
            batch.stored.push(self.index.put(&record)?);
            return Ok(());
        }
        if let Ok(m) = Manifest::from_record(&record) {
            batch.manifests.insert(*record.author(), m);
        }
        batch.pending.push(Pending { index, record, size });
        Ok(())
    }

    async fn stored_size(&self, address: &Address, author: &PublicKey) -> Result<Option<u64>> {
        let Some(record) = self.index.record(address)? else { return Ok(None) };
        if record.author() != author {
            return Err(Error::Refused("record by another author".to_owned()));
        }
        let mut size = record.to_bytes().len() as u64;
        if let Body::Blob(blob) = record.body() {
            size = size.saturating_add(self.blob_size(blob).await?);
        }
        Ok(Some(size))
    }

    async fn settle(&self, record: &Record, from: EndpointId, batch: &mut Batch) -> Result<()> {
        self.prepare(record, from, &batch.manifests).await?;
        let receipt = Receipt::from_record(record)?;
        if receipt.relay != self.key()? {
            return Err(Error::Refused("receipt is for another relay".to_owned()));
        }
        if self.allow.contains(record.author()) {
            batch.stored.push(self.index.put(record)?);
            return Ok(());
        }
        if self.pricing.banks.is_empty() {
            return Err(Error::Refused("relay takes no payment".to_owned()));
        }
        if !self.pricing.banks.contains(&receipt.voucher.bank) {
            return Err(Error::Refused("unknown bank".to_owned()));
        }
        let voucher = receipt.voucher.id();
        if self.index.spent(&voucher)? {
            return Err(Error::Refused("voucher already spent".to_owned()));
        }
        let now = now();
        if receipt.until <= now || receipt.until > now.saturating_add(MAX_DAYS * DAY) {
            return Err(Error::Refused("until out of range".to_owned()));
        }
        let days = (receipt.until - now).div_ceil(DAY);
        let mut total: u64 = 0;
        let mut covered = Vec::with_capacity(receipt.records.len());
        for address in &receipt.records {
            let size = match batch.pending.iter().position(|p| p.record.address() == *address) {
                Some(i) => {
                    if batch.pending[i].record.author() != record.author() {
                        return Err(Error::Refused("record by another author".to_owned()));
                    }
                    covered.push(i);
                    batch.pending[i].size
                }
                None => self
                    .stored_size(address, record.author())
                    .await?
                    .ok_or_else(|| Error::Refused(format!("{address} is not in the batch")))?,
            };
            total = cost(size, days, self.pricing.rate)
                .and_then(|c| total.checked_add(c))
                .ok_or_else(|| Error::Refused("cost overflows".to_owned()))?;
        }
        if receipt.voucher.cents < total {
            return Err(Error::Refused(format!(
                "underpaid: {total} cents for {days} days, voucher {}",
                receipt.voucher.cents
            )));
        }
        covered.sort_unstable_by(|a, b| b.cmp(a));
        let mut records: Vec<Record> =
            covered.iter().map(|&i| batch.pending.remove(i).record).collect();
        records.extend(manifest_for(record.author(), batch));
        records.push(record.clone());
        let mut pins = receipt.records.clone();
        pins.push(record.address());
        let settlement =
            Settlement { voucher, until: receipt.until, author: *record.author(), pins };
        let records: Vec<&Record> = records.iter().collect();
        self.index.commit(&records, Some(&settlement))?;
        batch.stored.extend(records.iter().map(|r| r.address()));
        Ok(())
    }
}

fn manifest_for(author: &PublicKey, batch: &mut Batch) -> Option<Record> {
    let i = batch.pending.iter().position(|p| {
        p.record.author() == author && p.record.kind() == weft_core::manifest::KIND
    })?;
    Some(batch.pending.remove(i).record)
}

impl ProtocolHandler for Relay {
    async fn accept(&self, connection: Connection) -> core::result::Result<(), AcceptError> {
        let from = connection.remote_id();
        loop {
            let Ok((mut send, mut recv)) = connection.accept_bi().await else { return Ok(()) };
            let response = match wire::recv(&mut recv).await.and_then(|b| Request::decode(&b)) {
                Ok(request) => self.handle(request, from).await,
                Err(e) => Response::Error { why: e.to_string() },
            };
            wire::send(&mut send, &response.encode()).await.map_err(AcceptError::from_err)?;
        }
    }
}
