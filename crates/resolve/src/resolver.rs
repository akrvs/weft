use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio::sync::OnceCell;
use tokio::time::timeout;
use weft_core::{Address, Body, Manifest, Pointer, PublicKey, Record, verify};
use weft_home::{Home, Reads, Store};
use weft_net::{Client, EndpointId};

use crate::dns::Dns;
use crate::error::{Error, Result};
use crate::render::{Links, render};
use crate::target::Target;

pub const RELAY_TIMEOUT: Duration = Duration::from_secs(5);
pub const BLOB_TIMEOUT: Duration = weft_home::store::PART_TTL;
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
struct Shared<R: Reads> {
    home: Home,
    reads: R,
    client: OnceCell<Client>,
    dns: OnceCell<Dns>,
}

#[derive(Debug)]
pub struct Resolver<R: Reads = Store> {
    shared: Arc<Shared<R>>,
    pulls: bool,
}

impl Resolver<Store> {
    pub fn local(home: Home) -> Self {
        let reads = home.store();
        Self::new(home, reads)
    }
}

impl<R: Reads> Resolver<R> {
    pub fn new(home: Home, reads: R) -> Self {
        Self::build(home, reads, OnceCell::new())
    }

    pub fn with_client(home: Home, reads: R, client: Client) -> Self {
        Self::build(home, reads, OnceCell::new_with(Some(client)))
    }

    fn build(home: Home, reads: R, client: OnceCell<Client>) -> Self {
        let shared = Shared { home, reads, client, dns: OnceCell::new() };
        Self { shared: Arc::new(shared), pulls: true }
    }

    #[must_use]
    pub fn offline(&self) -> Self {
        Self { shared: Arc::clone(&self.shared), pulls: false }
    }

    pub fn pulls(&self) -> bool {
        self.pulls
    }

    pub fn home(&self) -> &Home {
        &self.shared.home
    }

    pub fn reads(&self) -> &R {
        &self.shared.reads
    }

    pub async fn client(&self) -> Result<&Client> {
        Ok(self.shared.client.get_or_try_init(|| async { Client::bind().await }).await?)
    }

    pub async fn dns(&self) -> Result<&Dns> {
        self.shared
            .dns
            .get_or_try_init(|| async { Dns::new(std::env::var(DOH_ENV).ok().as_deref()) })
            .await
    }

    async fn relays(&self) -> Result<Option<(&Client, Vec<EndpointId>)>> {
        if !self.pulls {
            return Ok(None);
        }
        let relays = self.shared.home.relays()?;
        if relays.is_empty() {
            return Ok(None);
        }
        Ok(Some((self.client().await?, relays)))
    }

    pub async fn blob(&self, address: Address) -> Result<Option<Vec<u8>>> {
        if let Some(data) = self.reads().blob(address).await? {
            return Ok(Some(checked(address, data)?));
        }
        let Some((client, relays)) = self.relays().await? else { return Ok(None) };
        for relay in relays {
            let Ok(Ok(data)) = timeout(BLOB_TIMEOUT, client.pull_blob(relay, &address)).await
            else {
                continue;
            };
            let data = checked(address, data)?;
            self.reads().keep_blob(address, &data).await?;
            return Ok(Some(data));
        }
        Ok(None)
    }

    pub async fn local_manifest_record(&self, author: &PublicKey) -> Result<Option<Record>> {
        let Some(record) = self.reads().manifest(*author).await? else { return Ok(None) };
        if record.author() != author {
            return Ok(None);
        }
        verify(&record, None)?;
        Ok(Some(record))
    }

    pub async fn local_manifest(&self, author: &PublicKey) -> Result<Option<Manifest>> {
        match self.local_manifest_record(author).await? {
            Some(record) => Ok(Some(Manifest::from_record(&record)?)),
            None => Ok(None),
        }
    }

    pub async fn manifest(&self, author: &PublicKey) -> Result<Option<Manifest>> {
        if let Some(m) = self.local_manifest(author).await? {
            return Ok(Some(m));
        }
        let Some((client, relays)) = self.relays().await? else { return Ok(None) };
        for relay in relays {
            let Ok(Ok(head)) =
                timeout(RELAY_TIMEOUT, client.head(relay, *author, weft_core::pointer::MANIFEST))
                    .await
            else {
                continue;
            };
            if let Some(record) = head.manifest {
                if record.author() != author {
                    continue;
                }
                verify(&record, None)?;
                self.reads().keep(&record).await?;
                return Ok(Some(Manifest::from_record(&record)?));
            }
        }
        Ok(None)
    }

    pub async fn freshest_manifest(&self, author: &PublicKey) -> Result<Option<Manifest>> {
        let mut best = self.local_manifest(author).await?;
        let Some((client, relays)) = self.relays().await? else { return Ok(best) };
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
                self.reads().keep(&record).await?;
                best = Some(manifest);
            }
        }
        Ok(best)
    }

    pub async fn record(&self, address: Address) -> Result<(Record, String)> {
        if let Some(record) = self.reads().record(address).await? {
            return Ok((record, "local store".to_owned()));
        }
        let Some((client, relays)) = self.relays().await? else {
            return Err(Error::NotFound(address));
        };
        for relay in relays {
            if let Ok(Ok(Some(record))) = timeout(RELAY_TIMEOUT, client.get(relay, address)).await {
                return Ok((record, relay.to_string()));
            }
        }
        Err(Error::NotFound(address))
    }

    pub async fn head(&self, author: PublicKey, name: &str) -> Result<Address> {
        let manifest = self.manifest(&author).await?;
        let mut best: Option<(Record, Pointer)> = None;
        if let Some((client, relays)) = self.relays().await? {
            for relay in relays {
                let Ok(Ok(head)) = timeout(RELAY_TIMEOUT, client.head(relay, author, name)).await
                else {
                    continue;
                };
                let Some(record) = head.pointer else { continue };
                if let Some(candidate) = pointer_named(record, &author, name, manifest.as_ref())
                    && best.as_ref().is_none_or(|(r, p)| {
                        Pointer::compare((&candidate.0, &candidate.1), (r, p)).is_gt()
                    })
                {
                    best = Some(candidate);
                }
            }
        }
        let local: Vec<(Record, Pointer)> = self
            .reads()
            .pointers(author, name)
            .await?
            .into_iter()
            .filter_map(|r| pointer_named(r, &author, name, manifest.as_ref()))
            .collect();
        if let Some((r, p)) = Pointer::head(local.iter().map(|(r, p)| (r, p)))
            && best.as_ref().is_none_or(|(br, bp)| Pointer::compare((r, p), (br, bp)).is_gt())
        {
            best = Some((r.clone(), p.clone()));
        }
        let (record, pointer) = best.ok_or_else(|| Error::NoPointer(name.to_owned()))?;
        self.reads().keep(&record).await?;
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
        self.reads().keep(&record).await?;
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

fn checked(address: Address, data: Vec<u8>) -> Result<Vec<u8>> {
    if Address::of(&data) == address { Ok(data) } else { Err(Error::Blob(address)) }
}

fn pointer_named(
    record: Record,
    author: &PublicKey,
    name: &str,
    manifest: Option<&Manifest>,
) -> Option<(Record, Pointer)> {
    if record.author() != author || verify(&record, manifest).is_err() {
        return None;
    }
    let pointer = Pointer::from_record(&record).ok()?;
    (pointer.name == name).then_some((record, pointer))
}
