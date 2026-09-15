#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashSet;
use std::time::Duration;

use weft_net::{Client, Net, Pricing, Relay};

#[tokio::test]
async fn a_local_client_reaches_a_local_relay_by_id_alone() {
    let dir = std::env::temp_dir().join(format!("weft-local-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let ep = Net::Local.bind(None).await.unwrap();
    let relay =
        Relay::open(ep, &dir, HashSet::new(), Pricing::default(), Duration::from_secs(3600))
            .await
            .unwrap();
    let router = relay.clone().spawn();
    let id = router.endpoint().id();
    let client = Client::from_endpoint(Net::Local.bind(None).await.unwrap());
    let quote = tokio::time::timeout(Duration::from_secs(20), client.price(id))
        .await
        .expect("mdns lookup within 20 s")
        .unwrap();
    assert_eq!(quote.rate, Pricing::default().rate);
    assert!(quote.banks.is_empty());
    client.close().await;
    router.shutdown().await.unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
