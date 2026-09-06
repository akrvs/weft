#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::cast_possible_truncation)]

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};

use iroh::endpoint::{RelayMode, presets};
use iroh::{Endpoint, EndpointAddr};
use weft_core::{
    Address, Body, Device, Draft, Manifest, Pointer, PublicKey, Receipt, Record, SecretKey, Voucher,
};
use weft_net::relay::{cost, now};
use weft_net::{Client, Pricing, Relay};

async fn endpoint() -> Endpoint {
    Endpoint::builder(presets::Minimal).relay_mode(RelayMode::Disabled).bind().await.unwrap()
}

fn key(n: u8) -> SecretKey {
    SecretKey::from_seed([n; 32])
}

fn page(root: &SecretKey, signer: &SecretKey, body: &[u8], created: u64) -> Record {
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
    relay: Relay,
    router: iroh::protocol::Router,
    addr: EndpointAddr,
    dir: std::path::PathBuf,
}

impl Net {
    async fn start(allow: &[&SecretKey], rate: u64, banks: &[&SecretKey]) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "weft-pay-test-{}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let ep = endpoint().await;
        let allow: HashSet<_> = allow.iter().map(|k| k.public()).collect();
        let banks: HashSet<_> = banks.iter().map(|k| k.public()).collect();
        let relay = Relay::open(ep.clone(), &dir, allow, Pricing { rate, banks }).await.unwrap();
        let router = relay.clone().spawn();
        let addr = router.endpoint().addr();
        Self { relay, router, addr, dir }
    }

    fn key(&self) -> PublicKey {
        self.relay.key().unwrap()
    }

    async fn stop(self) {
        self.router.shutdown().await.unwrap();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn receipt(
    signer: &SecretKey,
    author: &SecretKey,
    relay: PublicKey,
    records: &[&Record],
    until: u64,
    voucher: Voucher,
) -> Record {
    let mut addresses: Vec<Address> = records.iter().map(|r| r.address()).collect();
    addresses.sort();
    Receipt { relay, records: addresses, until, voucher }
        .draft(&author.public(), &signer.public(), now())
        .sign(signer)
        .unwrap()
}

#[tokio::test]
async fn price_is_published() {
    let bank = key(9);
    let net = Net::start(&[], 3, &[&bank]).await;
    let c = Client::from_endpoint(endpoint().await);
    let (rate, banks) = c.price(net.addr.clone()).await.unwrap();
    assert_eq!(rate, 3);
    assert_eq!(banks, vec![bank.public()]);
    c.close().await;
    net.stop().await;
}

#[tokio::test]
async fn stranger_pays_to_pin_and_sweep_drops_it() {
    let root = key(1);
    let device = key(2);
    let bank = key(9);
    let net = Net::start(&[], 2, &[&bank]).await;
    let c = Client::from_endpoint(endpoint().await);
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
    let page_record = page(&root, &device, &[b'x'; 3000], 2_000);
    let pointer =
        Pointer { name: "home".into(), target: page_record.address(), seq: 1, prev: vec![] };
    let pointer_record =
        pointer.draft(&root.public(), &device.public(), 2_001).sign(&device).unwrap();

    let unpaid =
        c.put(net.addr.clone(), &[manifest_record.clone(), page_record.clone()]).await.unwrap();
    assert!(unpaid.stored.is_empty(), "{unpaid:?}");
    assert!(unpaid.rejected.iter().all(|(_, why)| why == "payment required"), "{unpaid:?}");
    assert!(c.get(net.addr.clone(), page_record.address()).await.unwrap().is_none());

    let until = now() + 3 * 86_400;
    let page_size = page_record.to_bytes().len() as u64;
    let pointer_size = pointer_record.to_bytes().len() as u64;
    let need = cost(page_size, 3, 2).unwrap() + cost(pointer_size, 3, 2).unwrap();
    assert_eq!(need, 5 * 3 * 2);

    let short = Voucher::mint(&bank, net.key(), need - 1, [1; 32]).unwrap();
    let cheap = receipt(&device, &root, net.key(), &[&page_record, &pointer_record], until, short);
    let batch = [manifest_record.clone(), page_record.clone(), pointer_record.clone(), cheap];
    let underpaid = c.put(net.addr.clone(), &batch).await.unwrap();
    assert!(underpaid.stored.is_empty(), "{underpaid:?}");
    assert!(
        underpaid
            .rejected
            .iter()
            .any(|(i, why)| *i == 3 && why.contains(&format!("underpaid: {need} cents"))),
        "{underpaid:?}"
    );

    let voucher = Voucher::mint(&bank, net.key(), need, [2; 32]).unwrap();
    let paid = receipt(
        &device,
        &root,
        net.key(),
        &[&page_record, &pointer_record],
        until,
        voucher.clone(),
    );
    let batch =
        [manifest_record.clone(), page_record.clone(), pointer_record.clone(), paid.clone()];
    let outcome = c.put(net.addr.clone(), &batch).await.unwrap();
    assert!(outcome.rejected.is_empty(), "{outcome:?}");
    assert_eq!(outcome.stored.len(), 4, "{outcome:?}");
    assert_eq!(
        c.get(net.addr.clone(), page_record.address()).await.unwrap(),
        Some(page_record.clone())
    );
    assert_eq!(c.get(net.addr.clone(), paid.address()).await.unwrap(), Some(paid.clone()));
    let head = c.head(net.addr.clone(), root.public(), "home").await.unwrap();
    assert_eq!(head.pointer, Some(pointer_record.clone()));
    assert_eq!(head.manifest, Some(manifest_record.clone()));

    let replay = receipt(&root, &root, net.key(), &[&page_record], until, voucher);
    let outcome = c.put(net.addr.clone(), &[replay]).await.unwrap();
    assert!(outcome.rejected.iter().any(|(_, why)| why.contains("already spent")), "{outcome:?}");

    let later = until + 86_400;
    let extension = Voucher::mint(&bank, net.key(), 100, [3; 32]).unwrap();
    let extend = receipt(&root, &root, net.key(), &[&page_record], later, extension);
    let outcome = c.put(net.addr.clone(), &[extend]).await.unwrap();
    assert!(outcome.rejected.is_empty(), "{outcome:?}");

    let swept = net.relay.sweep(until + 1).unwrap();
    assert_eq!(swept.records.len(), 2, "{swept:?}");
    assert!(swept.records.contains(&pointer_record.address()));
    assert!(swept.records.contains(&paid.address()));
    assert_eq!(
        c.get(net.addr.clone(), page_record.address()).await.unwrap(),
        Some(page_record.clone())
    );
    let head = c.head(net.addr.clone(), root.public(), "home").await.unwrap();
    assert_eq!(head.pointer, None);
    assert_eq!(head.manifest, Some(manifest_record.clone()));

    let swept = net.relay.sweep(later + 1).unwrap();
    assert_eq!(swept.records.len(), 3, "{swept:?}");
    assert!(swept.records.contains(&manifest_record.address()));
    assert!(c.get(net.addr.clone(), page_record.address()).await.unwrap().is_none());
    let head = c.head(net.addr.clone(), root.public(), "home").await.unwrap();
    assert_eq!(head.manifest, None);

    c.close().await;
    net.stop().await;
}

#[tokio::test]
async fn receipts_are_refused_for_the_wrong_relay_bank_or_author() {
    let root = key(1);
    let other = key(4);
    let bank = key(9);
    let rogue = key(8);
    let net = Net::start(&[], 1, &[&bank]).await;
    let c = Client::from_endpoint(endpoint().await);
    let page_record = page(&root, &root, b"hello", 2_000);
    let until = now() + 86_400;

    let elsewhere = Voucher::mint(&bank, key(7).public(), 50, [1; 32]).unwrap();
    let wrong_relay = Receipt {
        relay: key(7).public(),
        records: vec![page_record.address()],
        until,
        voucher: elsewhere,
    }
    .draft(&root.public(), &root.public(), now())
    .sign(&root)
    .unwrap();
    let outcome = c.put(net.addr.clone(), &[page_record.clone(), wrong_relay]).await.unwrap();
    assert!(outcome.rejected.iter().any(|(_, why)| why.contains("another relay")), "{outcome:?}");
    assert!(outcome.rejected.iter().any(|(_, why)| why == "payment required"), "{outcome:?}");

    let unknown = Voucher::mint(&rogue, net.key(), 50, [1; 32]).unwrap();
    let bad_bank = receipt(&root, &root, net.key(), &[&page_record], until, unknown);
    let outcome = c.put(net.addr.clone(), &[page_record.clone(), bad_bank]).await.unwrap();
    assert!(outcome.rejected.iter().any(|(_, why)| why.contains("unknown bank")), "{outcome:?}");

    let sponsor = Voucher::mint(&bank, net.key(), 50, [2; 32]).unwrap();
    let sponsored = receipt(&other, &other, net.key(), &[&page_record], until, sponsor);
    let outcome = c.put(net.addr.clone(), &[page_record.clone(), sponsored]).await.unwrap();
    assert!(outcome.rejected.iter().any(|(_, why)| why.contains("another author")), "{outcome:?}");

    let missing = Voucher::mint(&bank, net.key(), 50, [3; 32]).unwrap();
    let dangling = receipt(&root, &root, net.key(), &[&page_record], until, missing);
    let outcome = c.put(net.addr.clone(), &[dangling]).await.unwrap();
    assert!(
        outcome.rejected.iter().any(|(_, why)| why.contains("not in the batch")),
        "{outcome:?}"
    );

    let past = Voucher::mint(&bank, net.key(), 50, [4; 32]).unwrap();
    let expired = Receipt {
        relay: net.key(),
        records: vec![page_record.address()],
        until: 10,
        voucher: past,
    }
    .draft(&root.public(), &root.public(), 5)
    .sign(&root)
    .unwrap();
    let outcome = c.put(net.addr.clone(), &[page_record.clone(), expired]).await.unwrap();
    assert!(
        outcome.rejected.iter().any(|(_, why)| why.contains("until out of range")),
        "{outcome:?}"
    );

    let far = Voucher::mint(&bank, net.key(), u64::MAX, [5; 32]).unwrap();
    let forever = receipt(&root, &root, net.key(), &[&page_record], now() + 400 * 86_400, far);
    let outcome = c.put(net.addr.clone(), &[page_record.clone(), forever]).await.unwrap();
    assert!(
        outcome.rejected.iter().any(|(_, why)| why.contains("until out of range")),
        "{outcome:?}"
    );
    assert!(c.get(net.addr.clone(), page_record.address()).await.unwrap().is_none());

    c.close().await;
    net.stop().await;
}

#[tokio::test]
async fn allowlisted_authors_are_free_and_never_swept() {
    let root = key(1);
    let bank = key(9);
    let net = Net::start(&[&root], 1, &[&bank]).await;
    let c = Client::from_endpoint(endpoint().await);
    let page_record = page(&root, &root, b"free", 2_000);
    let voucher = Voucher::mint(&bank, net.key(), 1, [1; 32]).unwrap();
    let paid = receipt(&root, &root, net.key(), &[&page_record], now() + 60, voucher);
    let outcome = c.put(net.addr.clone(), &[page_record.clone(), paid]).await.unwrap();
    assert_eq!(outcome.stored.len(), 2, "{outcome:?}");
    let swept = net.relay.sweep(now() + 1_000_000).unwrap();
    assert!(swept.records.is_empty(), "{swept:?}");
    assert_eq!(c.get(net.addr.clone(), page_record.address()).await.unwrap(), Some(page_record));
    c.close().await;
    net.stop().await;
}

#[tokio::test]
async fn relay_without_banks_takes_no_payment() {
    let root = key(1);
    let bank = key(9);
    let net = Net::start(&[], 1, &[]).await;
    let c = Client::from_endpoint(endpoint().await);
    let page_record = page(&root, &root, b"nope", 2_000);
    let voucher = Voucher::mint(&bank, net.key(), 50, [1; 32]).unwrap();
    let paid = receipt(&root, &root, net.key(), &[&page_record], now() + 60, voucher);
    let outcome = c.put(net.addr.clone(), &[page_record, paid]).await.unwrap();
    assert!(outcome.stored.is_empty(), "{outcome:?}");
    assert!(
        outcome.rejected.iter().any(|(_, why)| why.contains("takes no payment")),
        "{outcome:?}"
    );
    c.close().await;
    net.stop().await;
}
