use std::path::Path;

use tokio::net::UnixStream;
use weft_core::{Address, Challenge, Proof, PublicKey, Record, SecretKey};

use crate::wire::{self, DOMAIN, MAX_BLOB, MAX_CHUNK, Request, Response};
use crate::{Error, Result};

#[derive(Debug)]
pub struct Client {
    stream: UnixStream,
}

impl Client {
    pub async fn connect(socket: &Path, key: &SecretKey) -> Result<Self> {
        let mut client = Self { stream: UnixStream::connect(socket).await? };
        let Response::Hello { nonce } = client.read().await? else {
            return Err(Error::Wire("expected hello"));
        };
        let sig = key.sign_in(DOMAIN, &nonce);
        match client.call(&Request::Auth { app: key.public(), sig }).await? {
            Response::Ok => Ok(client),
            _ => Err(Error::Wire("expected ok")),
        }
    }

    async fn read(&mut self) -> Result<Response> {
        let frame = wire::recv(&mut self.stream).await?.ok_or(Error::Wire("connection closed"))?;
        match Response::decode(&frame)? {
            Response::Error { why } => Err(Error::Remote(why)),
            response => Ok(response),
        }
    }

    async fn call(&mut self, request: &Request) -> Result<Response> {
        wire::send(&mut self.stream, &request.encode()).await?;
        self.read().await
    }

    pub async fn list(&mut self, kind: &str) -> Result<Vec<Address>> {
        match self.call(&Request::List { kind: kind.to_owned() }).await? {
            Response::List { addresses } => Ok(addresses),
            _ => Err(Error::Wire("expected list")),
        }
    }

    pub async fn get(&mut self, address: Address) -> Result<Record> {
        match self.call(&Request::Get { address }).await? {
            Response::Get { record } => Ok(Record::from_bytes(&record)?),
            _ => Err(Error::Wire("expected get")),
        }
    }

    pub async fn put(&mut self, kind: &str, body: Vec<u8>, refs: Vec<Address>) -> Result<Address> {
        match self.call(&Request::Put { kind: kind.to_owned(), body, refs }).await? {
            Response::Put { address } => Ok(address),
            _ => Err(Error::Wire("expected put")),
        }
    }

    pub async fn login(&mut self, challenge: &Challenge) -> Result<Proof> {
        match self.call(&Request::Login { challenge: challenge.encode() }).await? {
            Response::Login { proof } => Ok(Proof::decode(&proof)?),
            _ => Err(Error::Wire("expected login")),
        }
    }

    pub async fn kinds(&mut self) -> Result<Vec<(String, u64)>> {
        match self.call(&Request::Kinds).await? {
            Response::Kinds { kinds } => Ok(kinds),
            _ => Err(Error::Wire("expected kinds")),
        }
    }

    pub async fn grants(&mut self) -> Result<Vec<Record>> {
        match self.call(&Request::Grants).await? {
            Response::Grants { records } => decode_all(&records),
            _ => Err(Error::Wire("expected grants")),
        }
    }

    pub async fn revoke(&mut self, grant: Address) -> Result<Address> {
        match self.call(&Request::Revoke { grant }).await? {
            Response::Put { address } => Ok(address),
            _ => Err(Error::Wire("expected put")),
        }
    }

    pub async fn publish(&mut self, body: Vec<u8>, name: Option<&str>) -> Result<Vec<Record>> {
        match self.call(&Request::Publish { body, name: name.map(str::to_owned) }).await? {
            Response::Publish { records } => decode_all(&records),
            _ => Err(Error::Wire("expected publish")),
        }
    }
}

impl Client {
    pub async fn record(&mut self, address: Address) -> Result<Option<Record>> {
        self.one(&Request::Record { address }).await
    }

    pub async fn manifest(&mut self, author: PublicKey) -> Result<Option<Record>> {
        self.one(&Request::Manifest { author }).await
    }

    async fn one(&mut self, request: &Request) -> Result<Option<Record>> {
        match self.call(request).await? {
            Response::Get { record } => Ok(Some(Record::from_bytes(&record)?)),
            Response::Missing => Ok(None),
            _ => Err(Error::Wire("expected get or missing")),
        }
    }

    pub async fn pointers(&mut self, author: PublicKey, name: &str) -> Result<Vec<Record>> {
        match self.call(&Request::Pointers { author, name: name.to_owned() }).await? {
            Response::Records { records } => decode_all(&records),
            _ => Err(Error::Wire("expected records")),
        }
    }

    pub async fn blob(&mut self, address: Address) -> Result<Option<Vec<u8>>> {
        let mut data: Vec<u8> = Vec::new();
        let mut total = None;
        loop {
            let offset = u64::try_from(data.len()).map_err(|_| Error::Wire("blob too large"))?;
            match self.call(&Request::Blob { address, offset }).await? {
                Response::Missing if total.is_none() => return Ok(None),
                Response::Blob { total: t, chunk } => {
                    if t > MAX_BLOB || total.is_some_and(|known| known != t) {
                        return Err(Error::Wire("blob total changed or too large"));
                    }
                    if total.is_none() {
                        data.reserve_exact(
                            usize::try_from(t).map_err(|_| Error::Wire("blob too large"))?,
                        );
                        total = Some(t);
                    }
                    let end = offset.saturating_add(
                        u64::try_from(chunk.len()).map_err(|_| Error::Wire("chunk too large"))?,
                    );
                    if end > t || (chunk.is_empty() && end < t) {
                        return Err(Error::Wire("bad blob chunk"));
                    }
                    data.extend_from_slice(&chunk);
                    if end == t {
                        return Ok(Some(data));
                    }
                }
                _ => return Err(Error::Wire("expected blob")),
            }
        }
    }

    pub async fn keep(&mut self, record: &Record) -> Result<()> {
        self.ok(&Request::Keep { record: record.to_bytes() }).await
    }

    pub async fn keep_blob(&mut self, address: Address, data: &[u8]) -> Result<()> {
        let total = u64::try_from(data.len()).map_err(|_| Error::Wire("blob too large"))?;
        if total > MAX_BLOB {
            return Err(Error::Wire("blob too large"));
        }
        let mut offset = 0;
        loop {
            let chunk = &data[offset..data.len().min(offset + MAX_CHUNK)];
            let at = u64::try_from(offset).map_err(|_| Error::Wire("blob too large"))?;
            self.ok(&Request::KeepBlob { address, total, offset: at, chunk: chunk.to_vec() })
                .await?;
            offset += chunk.len();
            if offset >= data.len() {
                return Ok(());
            }
        }
    }

    async fn ok(&mut self, request: &Request) -> Result<()> {
        match self.call(request).await? {
            Response::Ok => Ok(()),
            _ => Err(Error::Wire("expected ok")),
        }
    }
}

fn decode_all(records: &[Vec<u8>]) -> Result<Vec<Record>> {
    records.iter().map(|r| Record::from_bytes(r).map_err(Error::Core)).collect()
}
