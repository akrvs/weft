use std::path::PathBuf;

use tokio::sync::Mutex;
use weft_core::{Address, PublicKey, Record};
use weft_home::{Fail, Reads};

use crate::gate::{browser_key, browser_key_path, socket_path};
use crate::{Client, Error, Result};

#[derive(Debug)]
pub struct Local {
    home: PathBuf,
    client: Mutex<Option<Client>>,
}

impl Local {
    pub fn new(home: PathBuf) -> Self {
        Self { home, client: Mutex::new(None) }
    }

    async fn connect(&self) -> Result<Client> {
        if !browser_key_path(&self.home).exists() {
            return Err(Error::Down);
        }
        let key = browser_key(&self.home)?;
        match Client::connect(&socket_path(&self.home), &key).await {
            Err(Error::Io(_)) => Err(Error::Down),
            other => other,
        }
    }

    pub async fn call<T>(&self, f: impl AsyncFnOnce(&mut Client) -> Result<T>) -> Result<T> {
        let mut slot = self.client.lock().await;
        if slot.is_none() {
            *slot = Some(self.connect().await?);
        }
        let Some(client) = slot.as_mut() else { return Err(Error::Down) };
        let result = f(client).await;
        if matches!(result, Err(Error::Io(_) | Error::Wire(_) | Error::Down)) {
            *slot = None;
        }
        result
    }
}

impl From<Error> for Fail {
    fn from(e: Error) -> Self {
        Self(e.to_string())
    }
}

impl Reads for Local {
    async fn record(&self, address: Address) -> weft_home::Result<Option<Record>> {
        Ok(self.call(async |c| c.record(address).await).await?)
    }

    async fn manifest(&self, author: PublicKey) -> weft_home::Result<Option<Record>> {
        Ok(self.call(async |c| c.manifest(author).await).await?)
    }

    async fn pointers(&self, author: PublicKey, name: &str) -> weft_home::Result<Vec<Record>> {
        Ok(self.call(async |c| c.pointers(author, name).await).await?)
    }

    async fn blob(&self, address: Address) -> weft_home::Result<Option<Vec<u8>>> {
        Ok(self.call(async |c| c.blob(address).await).await?)
    }

    async fn keep(&self, record: &Record) -> weft_home::Result<()> {
        Ok(self.call(async |c| c.keep(record).await).await?)
    }
}
