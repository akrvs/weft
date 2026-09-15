use std::path::Path;
use std::time::Duration;

use data_encoding::{BASE64, HEXLOWER};
use serde::Deserialize;
use weft_net::node::{Invoice, Issued, Node};
use weft_net::wire::MAX_BOLT11;

const TIMEOUT: Duration = Duration::from_secs(10);
const MAX_REPLY: usize = 64 * 1024;

#[derive(Debug)]
pub struct Lnd {
    url: String,
    macaroon: String,
    client: reqwest::Client,
}

#[derive(Deserialize)]
struct Added {
    r_hash: String,
    payment_request: String,
}

impl Lnd {
    pub fn open(url: &str, dir: &Path) -> Result<Self, String> {
        let url = url.trim_end_matches('/');
        if !url.starts_with("https://") {
            return Err("lnd url must be https".to_owned());
        }
        let macaroon = std::fs::read(dir.join("lnd.macaroon"))
            .map_err(|e| format!("lnd.macaroon: {e}"))
            .map(|bytes| HEXLOWER.encode(&bytes))?;
        let pem = std::fs::read(dir.join("lnd.pem")).map_err(|e| format!("lnd.pem: {e}"))?;
        let cert = reqwest::Certificate::from_pem(&pem).map_err(|e| format!("lnd.pem: {e}"))?;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = reqwest::Client::builder()
            .tls_certs_only([cert])
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(TIMEOUT)
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self { url: url.to_owned(), macaroon, client })
    }
}

impl Node for Lnd {
    fn invoice(&self, msat: u64, expiry: u64) -> Issued<'_> {
        Box::pin(async move {
            let body = serde_json::json!({
                "memo": "weft",
                "value_msat": msat.to_string(),
                "expiry": expiry.to_string(),
            });
            let response = self
                .client
                .post(format!("{}/v1/invoices", self.url))
                .header("Grpc-Metadata-macaroon", &self.macaroon)
                .header("content-type", "application/json")
                .body(body.to_string())
                .send()
                .await
                .map_err(net)?;
            let status = response.status();
            if !status.is_success() {
                return Err(weft_net::Error::Net(format!("lnd answered {status}")));
            }
            let bytes = response.bytes().await.map_err(net)?;
            if bytes.len() > MAX_REPLY {
                return Err(weft_net::Error::Net("lnd reply too large".to_owned()));
            }
            let added: Added = serde_json::from_slice(&bytes).map_err(net)?;
            let hash: [u8; 32] = BASE64
                .decode(added.r_hash.as_bytes())
                .ok()
                .and_then(|h| h.try_into().ok())
                .ok_or_else(|| weft_net::Error::Net("lnd r_hash is not 32 bytes".to_owned()))?;
            if added.payment_request.is_empty() || added.payment_request.len() > MAX_BOLT11 {
                return Err(weft_net::Error::Net("lnd payment_request out of range".to_owned()));
            }
            Ok(Invoice { bolt11: added.payment_request, hash })
        })
    }
}

fn net(e: impl std::fmt::Display) -> weft_net::Error {
    weft_net::Error::Net(e.to_string())
}
