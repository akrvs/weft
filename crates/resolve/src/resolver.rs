use std::time::Duration;

use serde::Serialize;
use tokio::sync::OnceCell;
use tokio::time::timeout;
use weft_core::{Address, Body, Manifest, Pointer, PublicKey, Record, verify};
use weft_home::{Home, Store};
use weft_net::Client;

use crate::dns::Dns;
use crate::error::{Error, Result};
use crate::render::{Links, render};
use crate::target::Target;

pub const RELAY_TIMEOUT: Duration = Duration::from_secs(5);
pub const DOH_ENV: &str = "WEFT_DOH";

#[derive(Debug, Clone, Serialize)]
pub struct Page {
    pub address: String,
    pub kind: String,
    pub author: String,
    pub signer: String,
    pub created: u64,
    pub source: String,
    pub name: String,
    pub html: String,
    pub blob: Option<String>,
}

#[derive(Debug)]
pub struct Resolver {
    home: Home,
    store: Store,
    client: OnceCell<Client>,
    dns: OnceCell<Dns>,
}

impl Resolver {
    pub fn new(home: Home) -> Self {
        let store = home.store();
        Self { home, store, client: OnceCell::new(), dns: OnceCell::new() }
    }

    pub fn home(&self) -> &Home {
        &self.home
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    pub async fn client(&self) -> Result<&Client> {
        Ok(self.client.get_or_try_init(|| async { Client::bind().await }).await?)
    }

    pub async fn dns(&self) -> Result<&Dns> {
        self.dns
            .get_or_try_init(|| async { Dns::new(std::env::var(DOH_ENV).ok().as_deref()) })
            .await
    }

    pub fn blob(&self, address: &Address) -> Option<Vec<u8>> {
        let data = std::fs::read(self.home.blob_path(address)).ok()?;
        (Address::of(&data) == *address).then_some(data)
    }

    pub fn local_manifest(&self, author: &PublicKey) -> Result<Option<Manifest>> {
        Ok(Store::manifest(&self.store.all()?, author))
    }

    pub async fn manifest(&self, author: &PublicKey) -> Result<Option<Manifest>> {
        if let Some(m) = self.local_manifest(author)? {
            return Ok(Some(m));
        }
        let client = self.client().await?;
        for relay in self.home.relays()? {
            let Ok(Ok(head)) =
                timeout(RELAY_TIMEOUT, client.head(relay, *author, weft_core::pointer::MANIFEST))
                    .await
            else {
                continue;
            };
            if let Some(record) = head.manifest {
                verify(&record, None)?;
                self.store.put(&record)?;
                return Ok(Some(Manifest::from_record(&record)?));
            }
        }
        Ok(None)
    }

    pub async fn freshest_manifest(&self, author: &PublicKey) -> Result<Option<Manifest>> {
        let mut best = self.local_manifest(author)?;
        let relays = self.home.relays()?;
        if relays.is_empty() {
            return Ok(best);
        }
        let client = self.client().await?;
        for relay in relays {
            let Ok(Ok(head)) =
                timeout(RELAY_TIMEOUT, client.head(relay, *author, weft_core::pointer::MANIFEST))
                    .await
            else {
                continue;
            };
            let Some(record) = head.manifest else { continue };
            if record.author() != author || verify(&record, None).is_err() {
                continue;
            }
            let manifest = Manifest::from_record(&record)?;
            if best.as_ref().is_none_or(|b| manifest.seq > b.seq) {
                self.store.put(&record)?;
                best = Some(manifest);
            }
        }
        Ok(best)
    }

    pub async fn record(&self, address: Address) -> Result<(Record, String)> {
        if let Some(record) = self.store.all()?.into_iter().find(|r| r.address() == address) {
            return Ok((record, "local store".to_owned()));
        }
        let client = self.client().await?;
        for relay in self.home.relays()? {
            if let Ok(Ok(Some(record))) = timeout(RELAY_TIMEOUT, client.get(relay, address)).await {
                return Ok((record, relay.to_string()));
            }
        }
        Err(Error::NotFound(address))
    }

    pub async fn head(&self, author: PublicKey, name: &str) -> Result<Address> {
        let manifest = self.manifest(&author).await?;
        let client = self.client().await?;
        let mut best: Option<(Record, Pointer)> = None;
        for relay in self.home.relays()? {
            let Ok(Ok(head)) = timeout(RELAY_TIMEOUT, client.head(relay, author, name)).await
            else {
                continue;
            };
            let Some(record) = head.pointer else { continue };
            if record.author() != &author || verify(&record, manifest.as_ref()).is_err() {
                continue;
            }
            let pointer = Pointer::from_record(&record)?;
            if pointer.name != name {
                continue;
            }
            if best
                .as_ref()
                .is_none_or(|(r, p)| Pointer::compare((&record, &pointer), (r, p)).is_gt())
            {
                best = Some((record, pointer));
            }
        }
        let records = self.store.all()?;
        let local = Store::pointers(&records, &author, name, manifest.as_ref());
        if let Some((r, p)) = Store::head(&local)
            && best.as_ref().is_none_or(|(br, bp)| Pointer::compare((r, p), (br, bp)).is_gt())
        {
            best = Some((r.clone(), p.clone()));
        }
        let (record, pointer) = best.ok_or_else(|| Error::NoPointer(name.to_owned()))?;
        self.store.put(&record)?;
        Ok(pointer.target)
    }

    pub async fn resolve(&self, target: Target, links: &Links) -> Result<Page> {
        let (address, name) = match target {
            Target::Address(address) => (address, "address".to_owned()),
            Target::Named { author, name } => {
                (self.head(author, &name).await?, format!("{}/{name}", author.address()))
            }
            Target::Domain { host, name } => {
                let binding = self.dns().await?.lookup(&host).await?;
                let tier = format!(
                    "{host}/{name} over dns, dnssec {}",
                    if binding.authentic { "verified" } else { "unverified" }
                );
                (self.head(binding.author, &name).await?, tier)
            }
        };
        let mut page = self.open(address, links).await?;
        page.name = name;
        Ok(page)
    }

    pub async fn open(&self, address: Address, links: &Links) -> Result<Page> {
        let (record, source) = self.record(address).await?;
        let manifest =
            if record.self_signed() { None } else { self.manifest(record.author()).await? };
        let verified = verify(&record, manifest.as_ref())?;
        self.store.put(&record)?;
        let (html, blob) = match record.body() {
            Body::Inline(bytes) if record.kind() == "page" => {
                (render(core::str::from_utf8(bytes).map_err(|_| Error::Text)?, links), None)
            }
            Body::Inline(bytes) => {
                let mut s = String::from("<pre>");
                s.push_str(&render(
                    &format!("```\n{}\n```", String::from_utf8_lossy(bytes)),
                    links,
                ));
                s.push_str("</pre>");
                (s, None)
            }
            Body::Blob(blob) => (String::new(), Some(blob.to_string())),
        };
        Ok(Page {
            address: verified.address.to_string(),
            kind: verified.kind,
            author: verified.author.to_string(),
            signer: verified.signer.to_string(),
            created: record.created(),
            source,
            name: "address".to_owned(),
            html,
            blob,
        })
    }
}
