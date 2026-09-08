#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::cast_possible_truncation)]

use std::collections::HashSet;
use std::path::PathBuf;

use iroh::address_lookup::MemoryLookup;
use iroh::endpoint::{RelayMode, presets};
use iroh::{Endpoint, EndpointAddr};
use weft_core::{Address, Body, Draft, Pointer, SecretKey};
use weft_home::{Home, Store};
use weft_net::{Client, Pricing, Relay};
use weft_resolve::{Error, Links, Resolver, Target};

const LINKS: Links = Links { record: "/", blob: "/blob/" };

fn key(n: u8) -> SecretKey {
    SecretKey::from_seed([n; 32])
}

fn temp(name: &str) -> PathBuf {
    let nanos =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let dir = std::env::temp_dir().join(format!("weft-pull-{}-{name}-{nanos}", std::process::id()));
    std::fs::create_dir_all(dir.join("records")).unwrap();
    std::fs::create_dir_all(dir.join("blobs")).unwrap();
    dir
}

async fn endpoint(known: Option<&EndpointAddr>) -> Endpoint {
    let builder = Endpoint::builder(presets::Minimal).relay_mode(RelayMode::Disabled);
    let builder = match known {
        Some(addr) => builder.address_lookup(MemoryLookup::from_endpoint_info([addr.clone()])),
        None => builder,
    };
    builder.bind().await.unwrap()
}

struct Site {
    router: iroh::protocol::Router,
    addr: EndpointAddr,
    root: SecretKey,
    page: Address,
    blob: Address,
    data: Vec<u8>,
    dirs: Vec<PathBuf>,
}

async fn publish() -> Site {
    let root = key(1);
    let relay_dir = temp("relay");
    let allow: HashSet<_> = [root.public()].into_iter().collect();
    let relay =
        Relay::open(endpoint(None).await, &relay_dir, allow, Pricing::default()).await.unwrap();
    let router = relay.spawn();
    let addr = router.endpoint().addr();
    let publisher = Client::from_endpoint(endpoint(Some(&addr)).await);
    let src_dir = temp("src");
    let data: Vec<u8> = (0..700_000u32).map(|i| (i % 253) as u8).collect();
    let src = src_dir.join("big.bin");
    std::fs::write(&src, &data).unwrap();
    let blob = publisher.add_blob(&src).await.unwrap();
    let page = Draft {
        author: root.public(),
        signer: root.public(),
        kind: "page".into(),
        created: 1_700_000_000,
        refs: vec![],
        body: Body::Inline(format!("# Pulled\n\n![img](weft:{blob})\n").into_bytes()),
    }
    .sign(&root)
    .unwrap();
    let file = Draft {
        author: root.public(),
        signer: root.public(),
        kind: "file".into(),
        created: 1_700_000_001,
        refs: vec![],
        body: Body::Blob(blob),
    }
    .sign(&root)
    .unwrap();
    let pointer = Pointer { name: "home".into(), target: page.address(), seq: 1, prev: vec![] }
        .draft(&root.public(), &root.public(), 1_700_000_002)
        .sign(&root)
        .unwrap();
    let outcome = publisher.put(addr.clone(), &[page.clone(), file, pointer]).await.unwrap();
    assert_eq!(outcome.rejected, vec![], "{outcome:?}");
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    publisher.close().await;
    Site { router, addr, root, page: page.address(), blob, data, dirs: vec![relay_dir, src_dir] }
}

async fn reader(site: &Site) -> (Resolver<Store>, PathBuf) {
    let dir = temp("reader");
    let home = Home::new(dir.clone());
    home.add_relay(site.addr.id).unwrap();
    let client = Client::from_endpoint(endpoint(Some(&site.addr)).await);
    let store = home.store();
    (Resolver::with_client(home, store, client), dir)
}

#[tokio::test]
async fn a_missing_blob_is_pulled_once_and_kept() {
    let site = publish().await;
    let (resolver, dir) = reader(&site).await;
    let blob_file = dir.join("blobs").join(site.blob.to_string());
    assert!(!blob_file.exists());
    let offline = resolver.offline();
    assert!(offline.blob(site.blob).await.unwrap().is_none());
    assert!(
        matches!(offline.open(site.page, &LINKS).await, Err(Error::NotFound(a)) if a == site.page)
    );
    let named = Target::Named { author: site.root.public(), name: "home".into() };
    assert!(
        matches!(offline.resolve(named, &LINKS).await, Err(Error::NoPointer(n)) if n == "home")
    );
    assert!(!blob_file.exists());
    assert_eq!(resolver.blob(site.blob).await.unwrap().unwrap(), site.data);
    assert_eq!(offline.blob(site.blob).await.unwrap().unwrap(), site.data);
    assert_eq!(std::fs::read(&blob_file).unwrap(), site.data);
    assert!(resolver.blob(Address::of(b"nowhere")).await.unwrap().is_none());
    let page = resolver
        .resolve(Target::Named { author: site.root.public(), name: "home".into() }, &LINKS)
        .await
        .unwrap();
    assert_eq!(page.address, site.page.to_string());
    assert!(page.html.contains(&format!("/blob/{}", site.blob)));
    site.router.shutdown().await.unwrap();
    assert_eq!(resolver.blob(site.blob).await.unwrap().unwrap(), site.data);
    let opened = resolver.open(site.page, &LINKS).await.unwrap();
    assert_eq!(opened.source, "local store");
    for d in site.dirs.iter().chain([&dir]) {
        let _ = std::fs::remove_dir_all(d);
    }
}

#[tokio::test]
async fn no_relays_means_a_plain_miss() {
    let dir = temp("offline");
    let home = Home::new(dir.clone());
    let store = home.store();
    let resolver = Resolver::new(home, store);
    assert!(resolver.blob(Address::of(b"nowhere")).await.unwrap().is_none());
    let _ = std::fs::remove_dir_all(&dir);
}
