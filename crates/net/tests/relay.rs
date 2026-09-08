#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::cast_possible_truncation)]

use std::collections::HashSet;

use iroh::endpoint::{RelayMode, presets};
use iroh::{Endpoint, EndpointAddr};
use weft_core::{Address, Body, Device, Draft, Manifest, Pointer, SecretKey, verify};
use weft_net::{Client, Pricing, Relay};

async fn endpoint() -> Endpoint {
    Endpoint::builder(presets::Minimal).relay_mode(RelayMode::Disabled).bind().await.unwrap()
}

fn key(n: u8) -> SecretKey {
    SecretKey::from_seed([n; 32])
}

fn page(root: &SecretKey, signer: &SecretKey, body: &[u8], created: u64) -> weft_core::Record {
    Draft {
        author: root.public(),
        signer: signer.public(),
        kind: "page".into(),
        created,
        refs: vec![],
        body: Body::Inline(body.to_vec()),
    }
    .sign(signer)
    .unwrap()
}

struct Net {
    router: iroh::protocol::Router,
    relay: Relay,
    addr: EndpointAddr,
    dir: std::path::PathBuf,
}

impl Net {
    async fn start(allow: &[&SecretKey]) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "weft-relay-test-{}-{}",
            std::process::id(),
            rand_suffix()
        ));
        let ep = endpoint().await;
        let allow: HashSet<_> = allow.iter().map(|k| k.public()).collect();
        let relay = Relay::open(ep.clone(), &dir, allow, Pricing::default()).await.unwrap();
        let router = relay.clone().spawn();
        let addr = router.endpoint().addr();
        Self { router, relay, addr, dir }
    }

    async fn stop(self) {
        self.router.shutdown().await.unwrap();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn rand_suffix() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64
}

#[tokio::test]
async fn publish_fetch_and_resolve_across_two_clients() {
    let root = key(1);
    let device = key(2);
    let stranger = key(3);
    let net = Net::start(&[&root]).await;
    let a = Client::from_endpoint(endpoint().await);
    let b = Client::from_endpoint(endpoint().await);

    let manifest = Manifest {
        seq: 1,
        prev: None,
        devices: vec![Device {
            key: device.public(),
            label: "laptop".into(),
            created: 1_000,
            expires: None,
        }],
        revoked: vec![],
    };
    let manifest_record = manifest.draft(&root.public(), 1_000).sign(&root).unwrap();
    let page_record = page(&root, &device, b"<h1>weft</h1>", 2_000);
    let pointer =
        Pointer { name: "home".into(), target: page_record.address(), seq: 1, prev: vec![] };
    let pointer_record =
        pointer.draft(&root.public(), &device.public(), 2_001).sign(&device).unwrap();
    let foreign = page(&stranger, &stranger, b"nope", 2_000);
    let orphan = page(&root, &key(4), b"unknown device", 2_000);
    let login = weft_core::Challenge { service: "http://x".into(), nonce: [1; 32], expires: 3_000 }
        .draft(&root.public(), &root.public(), 2_000)
        .sign(&root)
        .unwrap();

    let outcome = a
        .put(
            net.addr.clone(),
            &[
                page_record.clone(),
                manifest_record.clone(),
                pointer_record.clone(),
                foreign,
                orphan,
                login,
            ],
        )
        .await
        .unwrap();
    assert_eq!(outcome.stored.len(), 3, "{outcome:?}");
    assert_eq!(outcome.rejected.len(), 3, "{outcome:?}");
    assert!(outcome.rejected.iter().any(|(i, why)| *i == 3 && why.contains("payment required")));
    assert!(outcome.rejected.iter().any(|(i, why)| *i == 4 && why.contains("not authorized")));
    assert!(outcome.rejected.iter().any(|(i, why)| *i == 5 && why.contains("never relayed")));

    let fetched = b.get(net.addr.clone(), page_record.address()).await.unwrap().unwrap();
    assert_eq!(fetched, page_record);
    assert!(b.get(net.addr.clone(), Address::of(b"missing")).await.unwrap().is_none());

    let head = b.head(net.addr.clone(), root.public(), "home").await.unwrap();
    let head_manifest = Manifest::from_record(head.manifest.as_ref().unwrap()).unwrap();
    let head_pointer = head.pointer.unwrap();
    verify(&head_pointer, Some(&head_manifest)).unwrap();
    assert_eq!(Pointer::from_record(&head_pointer).unwrap().target, page_record.address());

    let revoking = Manifest {
        seq: 2,
        prev: Some(manifest_record.address()),
        devices: vec![],
        revoked: vec![device.public()],
    };
    let revoking_record = revoking.draft(&root.public(), 3_000).sign(&root).unwrap();
    a.put(net.addr.clone(), &[revoking_record]).await.unwrap();
    let head = b.head(net.addr.clone(), root.public(), "home").await.unwrap();
    let newest = Manifest::from_record(head.manifest.as_ref().unwrap()).unwrap();
    assert_eq!(newest.seq, 2);
    assert!(verify(&head_pointer, Some(&newest)).is_err());
    let late = a.put(net.addr.clone(), &[page(&root, &device, b"late", 3_500)]).await.unwrap();
    assert!(late.rejected.iter().any(|(_, why)| why.contains("revoked")), "{late:?}");

    a.close().await;
    b.close().await;
    net.stop().await;
}

#[tokio::test]
async fn blob_round_trip() {
    let root = key(1);
    let net = Net::start(&[&root]).await;
    let a = Client::from_endpoint(endpoint().await);
    let b = Client::from_endpoint(endpoint().await);

    let dir = std::env::temp_dir().join(format!(
        "weft-blob-test-{}-{}",
        std::process::id(),
        rand_suffix()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("big.bin");
    let data: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(&src, &data).unwrap();

    let blob = a.add_blob(&src).await.unwrap();
    assert_eq!(blob, Address::of(&data));
    let record = Draft {
        author: root.public(),
        signer: root.public(),
        kind: "file".into(),
        created: 1,
        refs: vec![],
        body: Body::Blob(blob),
    }
    .sign(&root)
    .unwrap();
    let outcome = a.put(net.addr.clone(), std::slice::from_ref(&record)).await.unwrap();
    assert_eq!(outcome.stored, vec![record.address()], "{outcome:?}");

    let fetched = b.get(net.addr.clone(), record.address()).await.unwrap().unwrap();
    let Body::Blob(hash) = fetched.body() else { panic!() };
    let out = dir.join("out.bin");
    let size = b.fetch_blob(net.addr.clone(), hash, &out).await.unwrap();
    assert_eq!(size, data.len() as u64);
    assert_eq!(std::fs::read(&out).unwrap(), data);

    a.close().await;
    b.close().await;
    net.stop().await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn reload_replaces_the_allow_list_and_pricing_for_the_next_batch() {
    let root = key(1);
    let stranger = key(2);
    let net = Net::start(&[&root]).await;
    let client = Client::from_endpoint(endpoint().await);
    let record = page(&stranger, &stranger, b"# Stranger", 1_700_000_000);
    let outcome = client.put(net.addr.clone(), std::slice::from_ref(&record)).await.unwrap();
    assert_eq!(outcome.stored, vec![]);
    assert_eq!(outcome.rejected.len(), 1, "{outcome:?}");
    let price = client.price(net.addr.clone()).await.unwrap();
    assert_eq!(price.0, 0);

    let allow: HashSet<_> = [root.public(), stranger.public()].into_iter().collect();
    let banks: HashSet<_> = [key(9).public()].into_iter().collect();
    net.relay.reload(allow.clone(), Pricing { rate: 3, banks: banks.clone() });
    assert_eq!(net.relay.config().allow, allow);
    let outcome = client.put(net.addr.clone(), std::slice::from_ref(&record)).await.unwrap();
    assert_eq!(outcome.stored, vec![record.address()], "{outcome:?}");
    let price = client.price(net.addr.clone()).await.unwrap();
    assert_eq!(price.0, 3);
    assert_eq!(price.1, vec![key(9).public()]);
    net.relay.reload(HashSet::new(), Pricing::default());
    let swept = net.relay.sweep(weft_net::relay::now()).unwrap();
    assert!(swept.records.is_empty(), "stored records outlive a delisting: {swept:?}");
    let outcome = client.put(net.addr.clone(), std::slice::from_ref(&record)).await.unwrap();
    assert_eq!(outcome.rejected.len(), 1, "a delisted author is refused again: {outcome:?}");
    client.close().await;
    net.stop().await;
}
