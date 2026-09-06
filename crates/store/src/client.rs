use std::path::Path;

use tokio::net::UnixStream;
use weft_core::{Address, Record, SecretKey};

use crate::wire::{self, DOMAIN, Request, Response};
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
}
