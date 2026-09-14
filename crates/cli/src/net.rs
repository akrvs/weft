use std::path::Path;

use weft_core::{Address, Body, Manifest, Pointer, PublicKey, Record, verify};
use weft_net::Client;

use weft_home::{Home, Relay, Result, Store, fail, fs};

fn relays(home: &Home) -> Result<Vec<Relay>> {
    let relays = home.relays()?;
    if relays.is_empty() {
        return fail("no relays configured; run `weft relay add <id>[@host:port]`");
    }
    Ok(relays)
}

async fn client() -> Result<Client> {
    Client::bind().await.map_err(|e| e.to_string().into())
}

#[derive(Debug)]
pub struct Paid {
    pub relay: Relay,
    pub receipt: Record,
}

pub async fn price(home: &Home) -> Result<()> {
    let relays = relays(home)?;
    let client = client().await?;
    for relay in relays {
        let (rate, banks) = client.price(&relay).await.map_err(|e| e.to_string())?;
        say!("{relay}  {rate} cents per KiB per day");
        for bank in banks {
            say!("  bank {}", bank.address());
        }
    }
    client.close().await;
    Ok(())
}

pub async fn push(
    home: &Home,
    store: &Store,
    addresses: &[Address],
    paid: Option<Paid>,
) -> Result<Vec<Address>> {
    let relays = match &paid {
        Some(p) => vec![p.relay.clone()],
        None => relays(home)?,
    };
    let snap = store.snapshot()?;
    let mut records: Vec<Record> = if addresses.is_empty() {
        snap.records().map(|r| (*r).clone()).collect()
    } else {
        addresses.iter().filter_map(|a| snap.find(*a)).map(|r| (*r).clone()).collect()
    };
    if records.is_empty() {
        return fail("nothing to push");
    }
    if let Some(p) = &paid {
        let root = home.root()?;
        if let Some(m) = snap.manifest_record(&root)
            && !records.contains(&m)
        {
            records.push((*m).clone());
        }
        records.push(p.receipt.clone());
    }
    records.sort_by_key(|r| {
        (r.kind() != weft_core::manifest::KIND, r.kind() == weft_core::receipt::KIND, r.created())
    });
    let client = client().await?;
    for record in &records {
        if let Body::Blob(address) = record.body() {
            let path = home.blob_path(address);
            if !path.is_file() {
                return fail(format!("blob {address} is not in the local store"));
            }
            let added = client.add_blob(&path).await.map_err(|e| e.to_string())?;
            if added != *address {
                return fail(format!("blob {address} does not match its file"));
            }
        }
    }
    let mut stored = Vec::new();
    for relay in relays {
        for batch in records.chunks(weft_net::wire::MAX_BATCH) {
            let outcome = client.put(&relay, batch).await.map_err(|e| e.to_string())?;
            say!("{relay}  stored {}  rejected {}", outcome.stored.len(), outcome.rejected.len());
            for (i, why) in outcome.rejected {
                let address =
                    usize::try_from(i).ok().and_then(|i| batch.get(i)).map(Record::address);
                say!("  {}  {why}", address.map_or(String::new(), |a| a.to_string()));
            }
            stored.extend(outcome.stored);
        }
    }
    client.close().await;
    Ok(stored)
}

async fn newest_manifest(
    client: &Client,
    relay: &Relay,
    author: PublicKey,
) -> Result<Option<Manifest>> {
    let head = client
        .head(relay, author, weft_core::pointer::MANIFEST)
        .await
        .map_err(|e| e.to_string())?;
    match head.manifest {
        Some(record) => {
            verify(&record, None)?;
            Ok(Some(Manifest::from_record(&record)?))
        }
        None => Ok(None),
    }
}

pub async fn fetch(home: &Home, store: &Store, address: Address, out: Option<&Path>) -> Result<()> {
    let relays = relays(home)?;
    let client = client().await?;
    let mut found = None;
    for relay in relays {
        if let Some(record) = client.get(&relay, address).await.map_err(|e| e.to_string())? {
            found = Some((relay, record));
            break;
        }
    }
    let Some((relay, record)) = found else {
        return fail(format!("{address} not found on any relay"));
    };
    let manifest = if record.self_signed() {
        None
    } else {
        newest_manifest(&client, &relay, *record.author()).await?
    };
    let verified = verify(&record, manifest.as_ref())?;
    let path = store.put(&record)?;
    say!("{}", path.display());
    say!("kind {}  author {}  signer {}", verified.kind, verified.author, verified.signer);
    if let Body::Blob(blob) = record.body() {
        let target = out.map_or_else(|| home.blob_path(blob), Path::to_path_buf);
        if let Some(parent) = target.parent() {
            fs::ensure_dir(parent)?;
        }
        let size = client.fetch_blob(&relay, blob, &target).await.map_err(|e| e.to_string())?;
        say!("blob {}  {size} bytes", target.display());
    } else if let (Some(out), Body::Inline(data)) = (out, record.body()) {
        fs::write(out, data)?;
        say!("body {}", out.display());
    }
    client.close().await;
    Ok(())
}

pub async fn resolve(home: &Home, store: &Store, author: Address, name: &str) -> Result<()> {
    let author = PublicKey::from_bytes(author.bytes())?;
    let relays = relays(home)?;
    let client = client().await?;
    let mut best: Option<(Record, Pointer)> = None;
    for relay in relays {
        let head = client.head(&relay, author, name).await.map_err(|e| e.to_string())?;
        let manifest = match head.manifest {
            Some(m) => {
                verify(&m, None)?;
                store.put(&m)?;
                Some(Manifest::from_record(&m)?)
            }
            None => None,
        };
        let Some(record) = head.pointer else { continue };
        if record.author() != &author || verify(&record, manifest.as_ref()).is_err() {
            continue;
        }
        let pointer = Pointer::from_record(&record)?;
        if pointer.name != name {
            continue;
        }
        let better = best
            .as_ref()
            .is_none_or(|(r, p)| Pointer::compare((&record, &pointer), (r, p)).is_gt());
        if better {
            best = Some((record, pointer));
        }
    }
    client.close().await;
    let Some((record, pointer)) = best else {
        return fail(format!("no valid pointer named {name} on any relay"));
    };
    store.put(&record)?;
    say!("{}", pointer.target);
    say!("seq {}  signer {}  pointer {}", pointer.seq, record.signer().address(), record.address());
    Ok(())
}
