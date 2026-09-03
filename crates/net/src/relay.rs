use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::{Endpoint, EndpointId};
use iroh_blobs::store::fs::FsStore;
use iroh_blobs::{BlobsProtocol, Hash};
use weft_core::{Body, Manifest, PublicKey, Record, verify};

use crate::error::net;
use crate::index::Index;
use crate::wire::{self, Request, Response};
use crate::{Error, Result};

#[derive(Debug, Clone)]
pub struct Relay {
    index: Arc<Index>,
    blobs: FsStore,
    allow: Arc<HashSet<PublicKey>>,
    endpoint: Endpoint,
}

impl Relay {
    pub async fn open(endpoint: Endpoint, dir: &Path, allow: HashSet<PublicKey>) -> Result<Self> {
        std::fs::create_dir_all(dir).map_err(|e| Error::Store(e.to_string()))?;
        let index = Arc::new(Index::open(&dir.join("index.redb"))?);
        let blobs =
            FsStore::load(dir.join("blobs")).await.map_err(|e| Error::Store(e.to_string()))?;
        Ok(Self { index, blobs, allow: Arc::new(allow), endpoint })
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
        }
    }

    async fn put(&self, records: Vec<Vec<u8>>, from: EndpointId) -> Response {
        let mut stored = Vec::new();
        let mut rejected = Vec::new();
        let mut parsed: Vec<(u64, Record)> = Vec::with_capacity(records.len());
        for (i, bytes) in (0u64..).zip(&records) {
            match Record::from_bytes(bytes) {
                Ok(r) => parsed.push((i, r)),
                Err(e) => rejected.push((i, e.to_string())),
            }
        }
        parsed.sort_by_key(|(_, r)| r.kind() != weft_core::manifest::KIND);
        for (i, record) in parsed {
            match self.store(&record, from).await {
                Ok(address) => stored.push(address),
                Err(e) => rejected.push((i, e.to_string())),
            }
        }
        rejected.sort_unstable_by_key(|(i, _)| *i);
        Response::Put { stored, rejected }
    }

    async fn store(&self, record: &Record, from: EndpointId) -> Result<weft_core::Address> {
        if !self.allow.contains(record.author()) {
            return Err(Error::Refused("author not allowed".to_owned()));
        }
        let manifest: Option<Manifest> = if record.self_signed() {
            None
        } else {
            self.index.manifest(record.author())?.map(|(_, m)| m)
        };
        verify(record, manifest.as_ref())?;
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
        }
        self.index.put(record)
    }
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
