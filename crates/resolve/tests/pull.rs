#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::cast_possible_truncation)]

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iroh::address_lookup::MemoryLookup;
use iroh::endpoint::{RelayMode, presets};
use iroh::{Endpoint, EndpointAddr};
use weft_core::recovery::{self, Signature};
use weft_core::{Address, Body, Draft, Guardians, Manifest, Pointer, Record, Recovery, SecretKey};
use weft_home::{Home, Store};
use weft_net::{Client, Pricing, Relay};
use weft_resolve::{Error, Links, Resolver, Target};

const LINKS: Links = Links { record: "/", blob: "/blob/" };

type Seen = (Address, u64, Option<u64>);

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

const HOUR: Duration = Duration::from_secs(3600);

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
    let relay = Relay::open(endpoint(None).await, &relay_dir, allow, Pricing::default(), HOUR)
        .await
        .unwrap();
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
    let entry =
        weft_home::Relay { id: site.addr.id, addrs: site.addr.ip_addrs().copied().collect() };
    home.add_relay(entry.to_string().parse().unwrap()).unwrap();
    let client = Client::from_endpoint(endpoint(None).await);
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
    let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
    let log = Arc::clone(&seen);
    let watched = resolver.watched(Arc::new(move |a, n, t| log.lock().unwrap().push((a, n, t))));
    assert_eq!(watched.blob(site.blob).await.unwrap().unwrap(), site.data);
    let seen: Vec<Seen> = std::mem::take(&mut *seen.lock().unwrap());
    assert!(!seen.is_empty());
    assert!(seen.iter().all(|(a, _, _)| *a == site.blob));
    assert!(seen.iter().all(|(_, _, t)| *t == Some(site.data.len() as u64)));
    assert!(seen.windows(2).all(|w| w[0].1 <= w[1].1));
    assert_eq!(seen.last().unwrap().1, site.data.len() as u64);
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

#[tokio::test]
async fn a_metered_handle_counts_only_pulled_bytes() {
    let site = publish().await;
    let (resolver, dir) = reader(&site).await;
    let meter = Arc::new(AtomicU64::new(0));
    let metered = resolver.metered(Arc::clone(&meter));
    assert!(metered.offline().blob(site.blob).await.unwrap().is_none());
    assert_eq!(meter.load(Ordering::Relaxed), 0, "a miss costs nothing");
    assert_eq!(metered.blob(site.blob).await.unwrap().unwrap(), site.data);
    assert_eq!(meter.load(Ordering::Relaxed), site.data.len() as u64);
    meter.store(0, Ordering::Relaxed);
    assert_eq!(resolver.open(site.page, &LINKS).await.unwrap().source, site.addr.id.to_string());
    assert_eq!(meter.load(Ordering::Relaxed), 0, "an unmetered handle never charges");
    let named = Target::Named { author: site.root.public(), name: "home".into() };
    let page = metered.resolve(named.clone(), &LINKS).await.unwrap();
    assert_eq!(page.address, site.page.to_string());
    let pointer_bytes = meter.swap(0, Ordering::Relaxed);
    assert!(pointer_bytes > 100, "the pointer pulled from the relay is charged: {pointer_bytes}");
    assert_eq!(metered.blob(site.blob).await.unwrap().unwrap(), site.data);
    assert_eq!(metered.open(site.page, &LINKS).await.unwrap().source, "local store");
    assert_eq!(meter.load(Ordering::Relaxed), 0, "local hits cost nothing");
    site.router.shutdown().await.unwrap();
    for d in site.dirs.iter().chain([&dir]) {
        let _ = std::fs::remove_dir_all(d);
    }
}

fn guarded(root: &SecretKey, guardian: &SecretKey) -> Record {
    Manifest {
        seq: 1,
        prev: None,
        devices: vec![],
        revoked: vec![],
        guardians: Some(Guardians { keys: vec![guardian.public()], threshold: 1 }),
    }
    .draft(&root.public(), 1_700_000_000)
    .sign(root)
    .unwrap()
}

fn recover(root: &SecretKey, to: &SecretKey, guardian: &SecretKey) -> Record {
    let message = recovery::message(&root.public(), &to.public(), 1, &[]);
    let sig =
        Signature { key: guardian.public(), sig: guardian.sign_in(recovery::DOMAIN, &message) };
    Recovery { to: to.public(), seq: 1, prev: vec![], sigs: vec![sig] }
        .draft(&root.public(), 1_700_000_003)
        .sign(to)
        .unwrap()
}

fn home_page(author: &SecretKey, body: &[u8]) -> (Record, Record) {
    let page = Draft {
        author: author.public(),
        signer: author.public(),
        kind: "page".into(),
        created: 1_700_000_001,
        refs: vec![],
        body: Body::Inline(body.to_vec()),
    }
    .sign(author)
    .unwrap();
    let pointer = Pointer { name: "home".into(), target: page.address(), seq: 1, prev: vec![] }
        .draft(&author.public(), &author.public(), 1_700_000_002)
        .sign(author)
        .unwrap();
    (page, pointer)
}

#[tokio::test]
async fn a_recovered_author_redirects_to_the_new_root() {
    let root = key(1);
    let new = key(2);
    let guardian = key(3);
    let relay_dir = temp("relay-recovery");
    let allow: HashSet<_> = [root.public(), new.public()].into_iter().collect();
    let relay = Relay::open(endpoint(None).await, &relay_dir, allow, Pricing::default(), HOUR)
        .await
        .unwrap();
    let router = relay.spawn();
    let addr = router.endpoint().addr();
    let publisher = Client::from_endpoint(endpoint(Some(&addr)).await);
    let (old_page, old_pointer) = home_page(&root, b"# Old\n");
    let (new_page, new_pointer) = home_page(&new, b"# New\n");
    let records = [
        guarded(&root, &guardian),
        recover(&root, &new, &guardian),
        old_page.clone(),
        old_pointer,
        new_page.clone(),
        new_pointer,
    ];
    let outcome = publisher.put(addr.clone(), &records).await.unwrap();
    assert_eq!(outcome.rejected, vec![], "{outcome:?}");
    publisher.close().await;

    let dir = temp("reader-recovery");
    let home = Home::new(dir.clone());
    let entry = weft_home::Relay { id: addr.id, addrs: addr.ip_addrs().copied().collect() };
    home.add_relay(entry.to_string().parse().unwrap()).unwrap();
    let store = home.store();
    let resolver = Resolver::with_client(home, store, Client::from_endpoint(endpoint(None).await));
    let target = Target::Named { author: root.public(), name: "home".into() };
    let page = resolver.resolve(target, &LINKS).await.unwrap();
    assert_eq!(page.author, new.public().address().to_string());
    assert_eq!(page.address, new_page.address().to_string());
    assert_eq!(resolver.offline().redirect(root.public()).await.unwrap(), new.public());
    assert_eq!(resolver.redirect(new.public()).await.unwrap(), new.public());
    let old = resolver.open(old_page.address(), &LINKS).await.unwrap();
    assert_eq!(old.author, root.public().address().to_string());

    router.shutdown().await.unwrap();
    for d in [relay_dir, dir] {
        let _ = std::fs::remove_dir_all(d);
    }
}

#[tokio::test]
async fn recovery_chains_stop_after_four_hops() {
    let dir = temp("hops");
    let store = Store::new(dir.clone());
    let resolver = Resolver::new(Home::new(dir.clone()), store.clone());
    let guardian = key(9);
    let keys: Vec<SecretKey> = (1..=6).map(key).collect();
    for pair in keys.windows(2).take(4) {
        store.put(&guarded(&pair[0], &guardian)).unwrap();
        store.put(&recover(&pair[0], &pair[1], &guardian)).unwrap();
    }
    assert_eq!(resolver.redirect(keys[0].public()).await.unwrap(), keys[4].public());
    store.put(&guarded(&keys[4], &guardian)).unwrap();
    store.put(&recover(&keys[4], &keys[5], &guardian)).unwrap();
    assert!(matches!(resolver.redirect(keys[0].public()).await, Err(Error::Hops(_))));
    assert_eq!(resolver.redirect(keys[1].public()).await.unwrap(), keys[5].public());
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn the_title_is_the_home_page_heading_read_locally() {
    let dir = temp("title");
    let store = Store::new(dir.clone());
    let resolver = Resolver::new(Home::new(dir.clone()), store.clone());
    let author = key(4);
    let named = |name: &str, body: &[u8], created: u64| {
        let page = Draft {
            author: author.public(),
            signer: author.public(),
            kind: "page".into(),
            created,
            refs: vec![],
            body: Body::Inline(body.to_vec()),
        }
        .sign(&author)
        .unwrap();
        let pointer =
            Pointer { name: name.into(), target: page.address(), seq: created, prev: vec![] }
                .draft(&author.public(), &author.public(), created)
                .sign(&author)
                .unwrap();
        store.put(&page).unwrap();
        store.put(&pointer).unwrap();
    };
    assert_eq!(resolver.title(&author.public()).await, None, "no page yet");
    named("home", b"# Far Away\n\nwelcome", 1);
    assert_eq!(resolver.title(&author.public()).await, Some("Far Away".to_owned()));
    named("home", b"no heading here", 2);
    assert_eq!(resolver.title(&author.public()).await, None, "the newest home has no title");
    assert_eq!(resolver.title(&key(5).public()).await, None, "an unknown author has none");
    let _ = std::fs::remove_dir_all(&dir);
}

fn own(
    root: &SecretKey,
    draft: impl Fn(&weft_core::PublicKey) -> Draft,
    name: &str,
) -> [Record; 2] {
    let list = draft(&root.public()).sign(root).unwrap();
    let pointer = Pointer { name: name.into(), target: list.address(), seq: 1, prev: vec![] }
        .draft(&root.public(), &root.public(), 1_700_000_010)
        .sign(root)
        .unwrap();
    [list, pointer]
}

#[tokio::test]
async fn a_petname_resolves_through_the_readers_own_list_only() {
    use weft_core::{Petnames, petname};
    let site = publish().await;
    let (resolver, dir) = reader(&site).await;
    let pet = Target::Petname { petname: "site".into(), name: "home".into() };
    assert!(resolver.petnames().await.unwrap().names.is_empty());
    assert!(
        matches!(resolver.resolve(pet.clone(), &LINKS).await, Err(Error::Petname(n)) if n == "site")
    );
    resolver.home().init(b"pass").unwrap();
    let me = resolver.home().open(weft_home::ROOT, b"pass").unwrap();
    let mut names = Petnames::default();
    names.insert("site", site.root.public()).unwrap();
    for r in own(&me, |a| names.draft(a, a, 1_700_000_009), petname::POINTER) {
        resolver.home().store().put(&r).unwrap();
    }
    let page = resolver.resolve(pet, &LINKS).await.unwrap();
    assert_eq!(page.address, site.page.to_string());
    assert_eq!(page.name, "site/home by petname");
    let other = Target::Petname { petname: "nobody".into(), name: "home".into() };
    assert!(matches!(resolver.resolve(other, &LINKS).await, Err(Error::Petname(_))));
    site.router.shutdown().await.unwrap();
    for d in site.dirs.iter().chain([&dir]) {
        let _ = std::fs::remove_dir_all(d);
    }
}

#[tokio::test]
async fn a_label_list_is_pulled_kept_and_bound_to_its_author() {
    use weft_core::{Label, Labels, label};
    let site = publish().await;
    let (resolver, dir) = reader(&site).await;
    let labeler = &site.root;
    let mut labels = Labels::default();
    labels.insert(Label { subject: site.page, value: "spam".into() }).unwrap();
    let records = own(labeler, |a| labels.draft(a, a, 1_700_000_009), label::POINTER);
    let publisher = Client::from_endpoint(endpoint(Some(&site.addr)).await);
    let outcome = publisher.put(site.addr.clone(), &records).await.unwrap();
    assert_eq!(outcome.rejected, vec![], "{outcome:?}");
    tokio::time::sleep(Duration::from_millis(500)).await;
    publisher.close().await;
    assert!(resolver.offline().labels(labeler.public()).await.unwrap().is_none());
    assert_eq!(resolver.labels(labeler.public()).await.unwrap(), Some(labels.clone()));
    site.router.shutdown().await.unwrap();
    assert_eq!(resolver.offline().labels(labeler.public()).await.unwrap(), Some(labels));

    let thief = key(9);
    let pointer =
        Pointer { name: label::POINTER.into(), target: records[0].address(), seq: 1, prev: vec![] }
            .draft(&thief.public(), &thief.public(), 1_700_000_011)
            .sign(&thief)
            .unwrap();
    resolver.home().store().put(&pointer).unwrap();
    assert!(matches!(
        resolver.offline().labels(thief.public()).await,
        Err(Error::Binding("list authored by another key"))
    ));
    for d in site.dirs.iter().chain([&dir]) {
        let _ = std::fs::remove_dir_all(d);
    }
}
