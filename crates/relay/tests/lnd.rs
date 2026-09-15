#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::cast_possible_truncation)]

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use data_encoding::{BASE64, HEXLOWER};
use iroh::Endpoint;
use iroh::endpoint::{RelayMode, presets};
use weft_core::receipt::payment_hash;
use weft_core::{Body, Draft, Payment, Receipt, SecretKey};
use weft_net::relay::{cost, now};
use weft_net::{Client, Pricing, Relay};
use weft_relay::lnd::Lnd;

async fn endpoint() -> Endpoint {
    Endpoint::builder(presets::Minimal).relay_mode(RelayMode::Disabled).bind().await.unwrap()
}

#[tokio::test]
#[ignore = "needs the regtest nodes from crates/relay/lnd.sh and WEFT_LND"]
async fn a_live_lnd_issues_an_invoice_that_a_payer_settles() {
    let dir = PathBuf::from(std::env::var_os("WEFT_LND").expect("WEFT_LND names lnd.sh's output"));
    let read = |name: &str| std::fs::read_to_string(dir.join(name)).unwrap().trim().to_owned();
    let node = Lnd::open(&read("url"), &dir).unwrap();
    let relay_dir = dir.join("relay");
    let _ = std::fs::remove_dir_all(&relay_dir);
    let pricing = Pricing { rate: 2, banks: HashSet::new(), sats: 10 };
    let relay = Relay::open(
        endpoint().await,
        &relay_dir,
        HashSet::new(),
        pricing,
        Duration::from_secs(3600),
    )
    .await
    .unwrap()
    .with_node(Arc::new(node));
    let router = relay.clone().spawn();
    let addr = router.endpoint().addr();
    let client = Client::from_endpoint(endpoint().await);

    let root = SecretKey::from_seed([1; 32]);
    let page = Draft {
        author: root.public(),
        signer: root.public(),
        kind: "page".into(),
        created: now(),
        refs: vec![],
        body: Body::Inline(vec![b'x'; 3000]),
    }
    .sign(&root)
    .unwrap();
    let need = cost(page.to_bytes().len() as u64, 3, 2).unwrap();
    assert_eq!(client.price(addr.clone()).await.unwrap().sats, 10);
    let offer = client.invoice(addr.clone(), need).await.unwrap();
    assert!(offer.bolt11.starts_with("lnbcrt"), "{}", offer.bolt11);
    assert!(offer.expires > now());

    let pem = std::fs::read(dir.join("payer.pem")).unwrap();
    let macaroon = HEXLOWER.encode(&std::fs::read(dir.join("payer.macaroon")).unwrap());
    let payer = reqwest::Client::builder()
        .use_preconfigured_tls(weft_relay::lnd::pinned(&pem).unwrap())
        .https_only(true)
        .timeout(Duration::from_secs(60))
        .build()
        .unwrap();
    let response = payer
        .post(format!("{}/v1/channels/transactions", read("payer.url")))
        .header("Grpc-Metadata-macaroon", &macaroon)
        .header("content-type", "application/json")
        .body(serde_json::json!({ "payment_request": offer.bolt11 }).to_string())
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success(), "{}", response.status());
    let sent: serde_json::Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    assert_eq!(sent["payment_error"].as_str().unwrap_or(""), "", "{sent}");
    let preimage: [u8; 32] = BASE64
        .decode(sent["payment_preimage"].as_str().unwrap().as_bytes())
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(payment_hash(&preimage), offer.hash);

    let until = now() + 3 * 86_400;
    let receipt = Receipt {
        relay: relay.key().unwrap(),
        records: vec![page.address()],
        until,
        payment: Payment::Preimage(preimage),
    }
    .draft(&root.public(), &root.public(), now())
    .sign(&root)
    .unwrap();
    let outcome = client.put(addr.clone(), &[page.clone(), receipt]).await.unwrap();
    assert_eq!(outcome.rejected, vec![], "{outcome:?}");
    assert_eq!(client.get(addr.clone(), page.address()).await.unwrap(), Some(page));

    client.close().await;
    router.shutdown().await.unwrap();
}
