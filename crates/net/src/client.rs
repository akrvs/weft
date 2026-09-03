use std::path::Path;

use iroh::endpoint::presets;
use iroh::protocol::Router;
use iroh::{Endpoint, EndpointAddr};
use iroh_blobs::store::mem::MemStore;
use iroh_blobs::{BlobsProtocol, Hash};
use weft_core::{Address, PublicKey, Record};

use crate::error::net;
use crate::wire::{self, Request, Response};
use crate::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PutOutcome {
    pub stored: Vec<Address>,
    pub rejected: Vec<(u64, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    pub pointer: Option<Record>,
    pub manifest: Option<Record>,
}

#[derive(Debug)]
pub struct Client {
    router: Router,
    blobs: MemStore,
}

impl Client {
    pub async fn bind() -> Result<Self> {
        let endpoint = Endpoint::bind(presets::N0).await.map_err(net)?;
        Ok(Self::from_endpoint(endpoint))
    }

    pub fn from_endpoint(endpoint: Endpoint) -> Self {
        let blobs = MemStore::new();
        let router = Router::builder(endpoint)
            .accept(iroh_blobs::ALPN, BlobsProtocol::new(&blobs, None))
            .spawn();
        Self { router, blobs }
    }

    pub fn endpoint(&self) -> &Endpoint {
        self.router.endpoint()
    }

    pub async fn add_blob(&self, path: &Path) -> Result<Address> {
        let abs = std::path::absolute(path).map_err(net)?;
        let tag = self.blobs.blobs().add_path(abs).await.map_err(net)?;
        Ok(Address::hash(*tag.hash.as_bytes()))
    }

    pub async fn fetch_blob(
        &self,
        relay: impl Into<EndpointAddr>,
        address: &Address,
        out: &Path,
    ) -> Result<u64> {
        let relay: EndpointAddr = relay.into();
        let hash = Hash::from_bytes(*address.bytes());
        self.blobs.downloader(self.endpoint()).download(hash, Some(relay.id)).await.map_err(net)?;
        let abs = std::path::absolute(out).map_err(net)?;
        self.blobs.blobs().export(hash, abs).await.map_err(net)
    }

    async fn call(&self, relay: impl Into<EndpointAddr>, request: &Request) -> Result<Response> {
        let conn = self.endpoint().connect(relay, wire::ALPN).await.map_err(net)?;
        let (mut send, mut recv) = conn.open_bi().await.map_err(net)?;
        wire::send(&mut send, &request.encode()).await?;
        let bytes = wire::recv(&mut recv).await?;
        conn.close(0u32.into(), b"done");
        match Response::decode(&bytes)? {
            Response::Error { why } => Err(Error::Refused(why)),
            response => Ok(response),
        }
    }

    pub async fn put(
        &self,
        relay: impl Into<EndpointAddr>,
        records: &[Record],
    ) -> Result<PutOutcome> {
        if records.len() > wire::MAX_BATCH {
            return Err(Error::Wire("batch too large"));
        }
        let request = Request::Put { records: records.iter().map(Record::to_bytes).collect() };
        match self.call(relay, &request).await? {
            Response::Put { stored, rejected } => Ok(PutOutcome { stored, rejected }),
            _ => Err(Error::Wire("unexpected response")),
        }
    }

    pub async fn get(
        &self,
        relay: impl Into<EndpointAddr>,
        address: Address,
    ) -> Result<Option<Record>> {
        match self.call(relay, &Request::Get { address }).await? {
            Response::Get { record: None } => Ok(None),
            Response::Get { record: Some(bytes) } => {
                let record = Record::from_bytes(&bytes)?;
                if record.address() != address {
                    return Err(Error::Wire("record does not match requested address"));
                }
                Ok(Some(record))
            }
            _ => Err(Error::Wire("unexpected response")),
        }
    }

    pub async fn head(
        &self,
        relay: impl Into<EndpointAddr>,
        author: PublicKey,
        name: &str,
    ) -> Result<Head> {
        match self.call(relay, &Request::Head { author, name: name.to_owned() }).await? {
            Response::Head { pointer, manifest } => Ok(Head {
                pointer: pointer.map(|b| Record::from_bytes(&b)).transpose()?,
                manifest: manifest.map(|b| Record::from_bytes(&b)).transpose()?,
            }),
            _ => Err(Error::Wire("unexpected response")),
        }
    }

    pub async fn close(self) {
        let _ = self.router.shutdown().await;
    }
}
