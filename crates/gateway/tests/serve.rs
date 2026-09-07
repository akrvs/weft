#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::too_many_lines)]

use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use weft_core::{Address, Body, Challenge, Device, Draft, Manifest, Pointer, Proof, SecretKey};
use weft_gateway::Gateway;
use weft_home::Home;
use weft_resolve::Resolver;

const PNG: &[u8] = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR";

struct Site {
    root: SecretKey,
    page: Address,
    blob: Address,
    file: Address,
    dir: PathBuf,
}

fn key(n: u8) -> SecretKey {
    SecretKey::from_seed([n; 32])
}

fn site() -> Site {
    let dir = std::env::temp_dir().join(format!(
        "weft-gateway-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir_all(dir.join("records")).unwrap();
    std::fs::create_dir_all(dir.join("blobs")).unwrap();
    let home = Home::new(dir.clone());
    let store = home.store();
    let root = key(1);
    let page = Draft {
        author: root.public(),
        signer: root.public(),
        kind: "page".into(),
        created: 1_700_000_000,
        refs: vec![],
        body: Body::Inline(b"# Hello\n\n<script>alert(1)</script>\n\n[x](weft:".to_vec()),
    };
    let mut body = page.body.clone();
    let Body::Inline(ref mut bytes) = body else { unreachable!() };
    bytes.extend_from_slice(Address::of(b"other").to_string().as_bytes());
    bytes.extend_from_slice(b")\n");
    let page = Draft { body, ..page }.sign(&root).unwrap();
    store.put(&page).unwrap();
    let pointer = Pointer { name: "home".into(), target: page.address(), seq: 1, prev: vec![] }
        .draft(&root.public(), &root.public(), 1_700_000_001)
        .sign(&root)
        .unwrap();
    store.put(&pointer).unwrap();
    let blob = Address::of(PNG);
    home.keep_blob(&blob, PNG).unwrap();
    let file = Draft {
        author: root.public(),
        signer: root.public(),
        kind: "file".into(),
        created: 1_700_000_002,
        refs: vec![],
        body: Body::Blob(blob),
    }
    .sign(&root)
    .unwrap();
    store.put(&file).unwrap();
    Site { root, page: page.address(), blob, file: file.address(), dir }
}

async fn start(site: &Site) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let gateway =
        Gateway::new(Resolver::local(Home::new(site.dir.clone())), format!("http://{addr}"))
            .unwrap();
    tokio::spawn(weft_gateway::serve(listener, Arc::new(gateway)));
    addr.to_string()
}

struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Reply {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

async fn request(addr: &str, method: &str, path: &str) -> Reply {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(
            format!("{method} {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.unwrap();
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8(raw[..split].to_vec()).unwrap();
    let mut lines = head.lines();
    let status = lines.next().unwrap().split(' ').nth(1).unwrap().parse().unwrap();
    let headers = lines
        .filter_map(|l| l.split_once(": "))
        .map(|(k, v)| (k.to_ascii_lowercase(), v.to_owned()))
        .collect();
    Reply { status, headers, body: raw[split + 4..].to_vec() }
}

#[tokio::test]
async fn serves_pages_blobs_and_names() {
    let site = site();
    let addr = start(&site).await;
    let root = site.root.public().address().to_string();

    let r = request(&addr, "GET", "/").await;
    assert_eq!(r.status, 200);
    assert!(r.text().contains("<form action=\"/go\""));
    assert!(r.header("content-security-policy").unwrap().contains("default-src 'none'"));

    let r = request(&addr, "GET", &format!("/{}", site.page)).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.header("x-weft-address").unwrap(), site.page.to_string());
    assert_eq!(r.header("x-weft-author").unwrap(), root);
    assert_eq!(r.header("x-weft-name").unwrap(), "address");
    assert_eq!(r.header("x-weft-source").unwrap(), "local store");
    let text = r.text();
    assert!(text.contains("<h1>Hello</h1>"));
    assert!(!text.contains("<script>"));
    assert!(text.contains(&format!("<a href=\"/{}\">x</a>", Address::of(b"other"))));
    assert!(text.contains("2023-11-14T22:13:20Z"));

    let r = request(&addr, "GET", &format!("/{root}/home")).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.header("x-weft-address").unwrap(), site.page.to_string());
    assert_eq!(r.header("x-weft-name").unwrap(), format!("{root}/home"));

    let r = request(&addr, "GET", &format!("/weft:{root}%2Fhome")).await;
    assert_eq!(r.status, 200);

    let r = request(&addr, "GET", &format!("/{}", site.file)).await;
    assert_eq!(r.status, 200);
    assert!(r.text().contains(&format!("<img src=\"/blob/{}\"", site.blob)));

    let r = request(&addr, "GET", &format!("/blob/{}", site.blob)).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.header("content-type").unwrap(), "image/png");
    assert_eq!(r.body, PNG);

    let r = request(&addr, "HEAD", &format!("/{}", site.page)).await;
    assert_eq!(r.status, 200);
    assert!(r.body.is_empty());
    assert_eq!(r.header("x-weft-address").unwrap(), site.page.to_string());

    let r = request(&addr, "GET", &format!("/go?q={root}%2Fhome")).await;
    assert_eq!(r.status, 303);
    assert_eq!(r.header("location").unwrap(), format!("/{root}/home"));

    let r = request(&addr, "GET", "/go?q=weft%3Aexample.com%2Fa+b").await;
    assert_eq!(r.status, 303);
    assert_eq!(r.header("location").unwrap(), "/example.com/a%20b");

    let _ = std::fs::remove_dir_all(&site.dir);
}

#[tokio::test]
async fn rejects_what_it_should() {
    let site = site();
    let addr = start(&site).await;
    let root = site.root.public().address().to_string();

    assert_eq!(request(&addr, "GET", &format!("/{root}/missing")).await.status, 404);
    assert_eq!(request(&addr, "GET", &format!("/{}", Address::of(b"nowhere"))).await.status, 404);
    assert_eq!(
        request(&addr, "GET", &format!("/blob/{}", Address::of(b"nowhere"))).await.status,
        404
    );
    assert_eq!(request(&addr, "GET", "/blob/junk").await.status, 400);
    let forged = Address::of(b"forged");
    Home::new(site.dir.clone()).keep_blob(&forged, b"not the bytes it names").unwrap();
    assert_eq!(request(&addr, "GET", &format!("/blob/{forged}")).await.status, 404);
    assert_eq!(request(&addr, "GET", "/notanaddress").await.status, 400);
    assert_eq!(request(&addr, "GET", "/../etc/passwd").await.status, 400);
    assert_eq!(request(&addr, "GET", "/%ff").await.status, 400);
    assert_eq!(request(&addr, "GET", "/go").await.status, 400);
    assert_eq!(request(&addr, "GET", &format!("/{}", "a".repeat(1100))).await.status, 414);
    let r = request(&addr, "POST", "/").await;
    assert_eq!(r.status, 405);
    assert_eq!(r.header("allow").unwrap(), "GET, HEAD");
    let r = request(&addr, "GET", &format!("/{}", Address::of(b"x"))).await;
    assert_eq!(r.header("x-content-type-options").unwrap(), "nosniff");

    let _ = std::fs::remove_dir_all(&site.dir);
}

async fn send(
    addr: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Reply {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n");
    for (k, v) in headers {
        let _ = write!(head, "{k}: {v}\r\n");
    }
    let _ = write!(head, "Content-Length: {}\r\n\r\n", body.len());
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.unwrap();
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let text = String::from_utf8(raw[..split].to_vec()).unwrap();
    let mut lines = text.lines();
    let status = lines.next().unwrap().split(' ').nth(1).unwrap().parse().unwrap();
    let headers = lines
        .filter_map(|l| l.split_once(": "))
        .map(|(k, v)| (k.to_ascii_lowercase(), v.to_owned()))
        .collect();
    Reply { status, headers, body: raw[split + 4..].to_vec() }
}

fn challenge_in(page: &str) -> Challenge {
    let start = page.find("weft:login?c=").unwrap() + 13;
    let end = start + page[start..].find('"').unwrap();
    Challenge::from_text(&page[start..end]).unwrap()
}

fn cookie_of(r: &Reply) -> String {
    r.header("set-cookie").unwrap().split(';').next().unwrap().to_owned()
}

#[tokio::test]
async fn login_round_trip() {
    let site = site();
    let addr = start(&site).await;
    let origin = format!("http://{addr}");
    let root = site.root.public();
    let now = weft_home::now().unwrap();

    let r = request(&addr, "GET", "/login").await;
    assert_eq!(r.status, 303);
    let location = r.header("location").unwrap().to_owned();
    assert!(location.starts_with("/login/"));
    let r = request(&addr, "GET", &location).await;
    assert_eq!(r.status, 200);
    let page = r.text();
    assert!(page.contains("http-equiv=\"refresh\""));
    let challenge = challenge_in(&page);
    assert_eq!(challenge.service, origin);
    assert!(challenge.expires > now);

    let sign = |c: &Challenge, key: &SecretKey| Proof {
        login: c.draft(&root, &key.public(), now).sign(key).unwrap(),
        manifest: None,
    };
    let elsewhere = Challenge { service: "http://evil".into(), ..challenge.clone() };
    let r =
        send(&addr, "POST", "/login", &[], sign(&elsewhere, &site.root).to_text().as_bytes()).await;
    assert_eq!(r.status, 403);
    let r = send(&addr, "POST", "/login", &[], b"not a proof").await;
    assert_eq!(r.status, 400);
    let stranger = key(9);
    let forged = Proof {
        login: challenge
            .draft(&stranger.public(), &stranger.public(), now)
            .sign(&stranger)
            .unwrap(),
        manifest: None,
    };
    let r = send(&addr, "POST", "/login", &[], forged.to_text().as_bytes()).await;
    assert_eq!(r.status, 200, "a stranger is a valid identity too");
    assert!(r.text().contains(&stranger.public().address().to_string()));
    let r =
        send(&addr, "POST", "/login", &[], sign(&challenge, &site.root).to_text().as_bytes()).await;
    assert_eq!(r.status, 403, "nonce is single use");
    let r = request(&addr, "GET", &location).await;
    assert_eq!(r.status, 200);
    assert!(r.text().contains(&stranger.public().address().to_string()));
    let cookie = cookie_of(&r);
    let r = request(&addr, "GET", &location).await;
    assert_eq!(r.status, 403);

    let r = send(&addr, "GET", "/login", &[("Cookie", &cookie)], b"").await;
    assert_eq!(r.status, 200);
    assert!(r.text().contains("Logged in"));
    let r = send(&addr, "POST", "/logout", &[("Cookie", &cookie)], b"").await;
    assert_eq!(r.status, 303);
    assert!(r.header("set-cookie").unwrap().contains("Max-Age=0"));
    let r = send(&addr, "GET", "/login", &[("Cookie", &cookie)], b"").await;
    assert_eq!(r.status, 303);

    let r = request(&addr, "GET", "/login").await;
    let location = r.header("location").unwrap().to_owned();
    let challenge = challenge_in(&request(&addr, "GET", &location).await.text());
    let proof = sign(&challenge, &site.root).to_text();
    let form = format!("x=1&p={proof}");
    let r = send(
        &addr,
        "POST",
        "/login",
        &[("Content-Type", "application/x-www-form-urlencoded")],
        form.as_bytes(),
    )
    .await;
    assert_eq!(r.status, 200);
    assert!(r.text().contains(&root.address().to_string()));
    let set = r.header("set-cookie").unwrap();
    assert!(set.contains("HttpOnly") && set.contains("SameSite=Strict"));

    let device = key(2);
    let manifest = Manifest {
        seq: 1,
        prev: None,
        devices: vec![Device {
            key: device.public(),
            label: "d".into(),
            created: 1,
            expires: None,
        }],
        revoked: vec![],
    };
    let manifest_record = manifest.draft(&root, 1).sign(&site.root).unwrap();
    let by_device = |c: &Challenge| Proof {
        login: c.draft(&root, &device.public(), now).sign(&device).unwrap(),
        manifest: Some(manifest_record.clone()),
    };
    let r = request(&addr, "GET", "/login").await;
    let challenge =
        challenge_in(&request(&addr, "GET", r.header("location").unwrap()).await.text());
    let r = send(&addr, "POST", "/login", &[], by_device(&challenge).to_text().as_bytes()).await;
    assert_eq!(r.status, 200);
    assert!(r.text().contains(&root.address().to_string()));

    let revoking = Manifest {
        seq: 2,
        prev: Some(manifest_record.address()),
        devices: vec![],
        revoked: vec![device.public()],
    };
    Home::new(site.dir.clone())
        .store()
        .put(&revoking.draft(&root, 2).sign(&site.root).unwrap())
        .unwrap();
    let r = request(&addr, "GET", "/login").await;
    let challenge =
        challenge_in(&request(&addr, "GET", r.header("location").unwrap()).await.text());
    let r = send(&addr, "POST", "/login", &[], by_device(&challenge).to_text().as_bytes()).await;
    assert_eq!(r.status, 403, "the newer local manifest revokes the device");
    assert!(r.text().contains("revoked"));

    let big = vec![b'A'; weft_gateway::MAX_BODY + 1];
    let r = send(&addr, "POST", "/login", &[], &big).await;
    assert_eq!(r.status, 413);
    let r = send(&addr, "POST", &format!("/{}", site.page), &[], b"").await;
    assert_eq!(r.status, 405);
    let r = request(&addr, "GET", "/login/zzz").await;
    assert_eq!(r.status, 400);

    let _ = std::fs::remove_dir_all(&site.dir);
}
