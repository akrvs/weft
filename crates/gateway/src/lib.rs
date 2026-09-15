#![forbid(unsafe_code)]

pub mod budget;
pub mod html;
pub mod login;
pub mod state;

use std::collections::HashSet;
use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http::header::{
    ALLOW, CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_SECURITY_POLICY, CONTENT_TYPE, COOKIE, HOST,
    HeaderName, HeaderValue, LOCATION, REFERRER_POLICY, SET_COOKIE, X_CONTENT_TYPE_OPTIONS,
};
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use percent_encoding::{AsciiSet, CONTROLS, percent_decode_str, utf8_percent_encode};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use weft_core::{Address, Proof, PublicKey, login as text};
use weft_resolve::{Error, Links, Page, Resolver, Target};
use weft_store::Local;

use crate::budget::Budget;
use crate::login::{Claim, Logins, Refusal, Token, token_from_cookies};
use crate::state::State;

pub const LINKS: Links = Links { record: "/", blob: "/blob/" };
pub const MAX_PATH: usize = 1024;
pub const MAX_BUF: usize = 16 * 1024;
pub const MAX_BODY: usize = text::MAX_PROOF * 4 / 3 + 1024;
pub const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
pub const MAX_PULLS: usize = 4;
pub const LOGIN_TO_FETCH: &str = "; log in to fetch from relays";
pub const BUDGET_SPENT: &str = "; pull budget spent, resets at ";
const CSP: &str = "default-src 'none'; img-src 'self'; style-src 'self'; form-action 'self'; frame-ancestors 'none'";
const PATH: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}');

pub type Reply = Response<Full<Bytes>>;
type Fail = (StatusCode, String);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub pulls: usize,
    pub budget: u64,
    pub sessions: usize,
    pub identities: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            pulls: MAX_PULLS,
            budget: budget::DEFAULT_BYTES,
            sessions: login::DEFAULT_SESSIONS,
            identities: budget::DEFAULT_IDENTITIES,
        }
    }
}

#[derive(Debug)]
pub struct Gateway {
    pub resolver: Resolver<Local>,
    pub logins: Logins,
    pub budget: Budget,
    pulls: Semaphore,
}

impl Gateway {
    pub fn new(
        resolver: Resolver<Local>,
        origin: String,
        allow: Option<HashSet<PublicKey>>,
        limits: Limits,
    ) -> Result<Self, Refusal> {
        let now = weft_home::now().map_err(|e| Refusal::State(e.to_string()))?;
        let state = Arc::new(State::open(resolver.home().path())?);
        let logins = Logins::new(origin, Arc::clone(&state), allow, limits.sessions, now)?;
        let budget = Budget::open(state, limits.budget, budget::WINDOW, limits.identities, now)?;
        Ok(Self { resolver, logins, budget, pulls: Semaphore::new(limits.pulls) })
    }
}

fn down(e: &Error) -> bool {
    matches!(e, Error::Home(f) if f.to_string() == weft_store::Error::Down.to_string())
}

pub async fn serve(listener: TcpListener, gateway: Arc<Gateway>) -> std::io::Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let gateway = Arc::clone(&gateway);
        tokio::spawn(async move {
            let service = service_fn(move |req| handle(Arc::clone(&gateway), req));
            let _ = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(HEADER_TIMEOUT)
                .max_buf_size(MAX_BUF)
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}

pub async fn handle(gateway: Arc<Gateway>, req: Request<Incoming>) -> Result<Reply, Infallible> {
    let head = req.method() == Method::HEAD;
    let token =
        req.headers().get(COOKIE).and_then(|v| v.to_str().ok()).and_then(token_from_cookies);
    let host = req.headers().get(HOST).and_then(|v| v.to_str().ok()).map(str::to_ascii_lowercase);
    let host = host.as_deref();
    let path = req.uri().path().to_owned();
    let mut reply = match (req.method(), path.as_str()) {
        (&Method::POST, "/login") => match body(req).await {
            Ok(text) => post_login(&gateway, &text, host).await,
            Err(f) => failed(f),
        },
        (&Method::POST, "/logout") => logout(&gateway.logins, token.as_ref()),
        (&Method::GET | &Method::HEAD, "/login") => {
            login_page(&gateway.logins, token.as_ref(), host)
        }
        (&Method::GET | &Method::HEAD, _) if path.starts_with("/login/") => {
            claim(&gateway.logins, &path[7..], host)
        }
        (&Method::GET | &Method::HEAD, _) => {
            let publisher = publisher(&gateway.logins, host);
            read(&gateway, token.as_ref(), &path, req.uri().query(), publisher.as_deref()).await
        }
        _ => {
            let mut r =
                html_reply(StatusCode::METHOD_NOT_ALLOWED, html::error(405, "method not allowed"));
            r.headers_mut().insert(ALLOW, HeaderValue::from_static("GET, HEAD"));
            r
        }
    };
    if head {
        *reply.body_mut() = Full::default();
    }
    Ok(reply)
}

fn bare_host(host: &str) -> &str {
    if host.starts_with('[') {
        host.split_once(']').map_or(host, |(v6, _)| &v6[1..])
    } else {
        host.rsplit_once(':').map_or(host, |(name, _)| name)
    }
}

fn publisher(logins: &Logins, host: Option<&str>) -> Option<String> {
    let host = bare_host(host?);
    let origin = logins.origin().split_once("://").map_or("", |(_, rest)| rest);
    let origin = bare_host(origin.split('/').next().unwrap_or(""));
    let numeric = host.rsplit('.').next().is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()));
    if host == origin || numeric {
        return None;
    }
    match format!("{host}/home").parse::<Target>() {
        Ok(Target::Domain { host, .. }) => Some(host),
        _ => None,
    }
}

async fn read(
    gateway: &Gateway,
    token: Option<&Token>,
    path: &str,
    query: Option<&str>,
    publisher: Option<&str>,
) -> Reply {
    let now = match now() {
        Ok(now) => now,
        Err(f) => return failed(f),
    };
    let Some(author) = token.and_then(|t| gateway.logins.session(t, now)) else {
        return route(&gateway.resolver.offline(), LOGIN_TO_FETCH, path, query, publisher).await;
    };
    if let Some(reset) = gateway.budget.spent(&author, now) {
        let hint = format!("{BUDGET_SPENT}{}", html::iso(reset));
        return route(&gateway.resolver.offline(), &hint, path, query, publisher).await;
    }
    match gateway.pulls.try_acquire() {
        Ok(_permit) => {
            let meter = Arc::new(AtomicU64::new(0));
            let metered = gateway.resolver.metered(Arc::clone(&meter));
            let reply = route(&metered, "", path, query, publisher).await;
            if let Err(e) = gateway.budget.charge(author, now, meter.load(Ordering::Relaxed)) {
                eprintln!("budget: {e}");
            }
            reply
        }
        Err(_) => html_reply(
            StatusCode::TOO_MANY_REQUESTS,
            html::error(429, "too many fetches in flight"),
        ),
    }
}

fn missing(what: &str, hint: &str) -> Reply {
    let mut message = what.to_owned();
    message.push_str(hint);
    html_reply(StatusCode::NOT_FOUND, html::error(404, &message))
}

async fn route(
    resolver: &Resolver<Local>,
    hint: &str,
    path: &str,
    query: Option<&str>,
    publisher: Option<&str>,
) -> Reply {
    if path.len() > MAX_PATH {
        return html_reply(StatusCode::URI_TOO_LONG, html::error(414, "path too long"));
    }
    match (path, publisher) {
        ("/", Some(host)) => page(resolver, hint, host, None).await,
        ("/", None) => html_reply(StatusCode::OK, html::form()),
        ("/style.css", _) => {
            let mut r = reply(StatusCode::OK, "text/css; charset=utf-8", html::STYLE.into());
            r.headers_mut()
                .insert(CACHE_CONTROL, HeaderValue::from_static("public, max-age=86400"));
            r
        }
        ("/go", _) => go(query),
        _ if path.starts_with("/blob/") => blob(resolver, hint, &path[6..]).await,
        _ => page(resolver, hint, &path[1..], publisher).await,
    }
}

fn go(query: Option<&str>) -> Reply {
    let q = query
        .into_iter()
        .flat_map(|q| q.split('&'))
        .find_map(|pair| pair.strip_prefix("q="))
        .map(|v| v.replace('+', " "))
        .and_then(|v| percent_decode_str(&v).decode_utf8().ok().map(|s| s.trim().to_owned()));
    let Some(q) = q.filter(|q| !q.is_empty()) else {
        return html_reply(StatusCode::BAD_REQUEST, html::error(400, "nothing to open"));
    };
    let q = q.strip_prefix("weft:").unwrap_or(&q);
    let location = format!("/{}", utf8_percent_encode(q, PATH));
    let mut r = html_reply(StatusCode::SEE_OTHER, html::error(303, &location));
    if let Ok(v) = HeaderValue::from_str(&location) {
        r.headers_mut().insert(LOCATION, v);
    }
    r
}

async fn blob(resolver: &Resolver<Local>, hint: &str, rest: &str) -> Reply {
    let Ok(address) = rest.parse::<Address>() else {
        return html_reply(StatusCode::BAD_REQUEST, html::error(400, "not a blob address"));
    };
    let data = match resolver.blob(address).await {
        Ok(Some(data)) => data,
        Ok(None) => return missing("blob not found", hint),
        Err(e) if down(&e) => {
            return html_reply(StatusCode::SERVICE_UNAVAILABLE, html::error(503, &e.to_string()));
        }
        Err(e) => return html_reply(StatusCode::BAD_GATEWAY, html::error(502, &e.to_string())),
    };
    let kind = sniff(&data);
    let mut r = reply(StatusCode::OK, kind, data.into());
    r.headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("public, max-age=31536000, immutable"));
    if kind == "application/octet-stream" {
        r.headers_mut().insert(CONTENT_DISPOSITION, HeaderValue::from_static("attachment"));
    }
    r
}

fn target_for(input: &str, publisher: Option<&str>) -> Result<(Target, String), Error> {
    match (input.parse::<Target>(), publisher) {
        (Ok(t), _) => Ok((t, input.to_owned())),
        (Err(e), Some(host)) => {
            let under = format!("{host}/{input}");
            under.parse().map(|t| (t, under)).map_err(|_| e)
        }
        (Err(e), None) => Err(e),
    }
}

async fn page(
    resolver: &Resolver<Local>,
    hint: &str,
    rest: &str,
    publisher: Option<&str>,
) -> Reply {
    let Ok(input) = percent_decode_str(rest).decode_utf8() else {
        return html_reply(StatusCode::BAD_REQUEST, html::error(400, "path is not utf-8"));
    };
    let (target, input) = match target_for(&input, publisher) {
        Ok(found) => found,
        Err(e) => return html_reply(StatusCode::BAD_REQUEST, html::error(400, &e.to_string())),
    };
    match resolver.resolve(target, &LINKS).await {
        Ok(page) => {
            let mut r = html_reply(StatusCode::OK, html::page(&page, &input));
            provenance(&mut r, &page);
            r
        }
        Err(e) => {
            let status = match e {
                _ if down(&e) => StatusCode::SERVICE_UNAVAILABLE,
                Error::Target(_) => StatusCode::BAD_REQUEST,
                Error::NotFound(_) | Error::NoPointer(_) => {
                    return missing(&e.to_string(), hint);
                }
                Error::Dns(_) | Error::Binding(_) | Error::Hops(_) => StatusCode::NOT_FOUND,
                Error::Core(_) | Error::Net(_) | Error::Text | Error::Blob(_) => {
                    StatusCode::BAD_GATEWAY
                }
                Error::Home(_) => StatusCode::INTERNAL_SERVER_ERROR,
            };
            html_reply(status, html::error(status.as_u16(), &e.to_string()))
        }
    }
}

async fn body(req: Request<Incoming>) -> Result<String, Fail> {
    let form = req
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("application/x-www-form-urlencoded"));
    let bytes = Limited::new(req.into_body(), MAX_BODY)
        .collect()
        .await
        .map_err(|_| (StatusCode::PAYLOAD_TOO_LARGE, "body too large".to_owned()))?
        .to_bytes();
    let text = String::from_utf8(bytes.to_vec())
        .map_err(|_| (StatusCode::BAD_REQUEST, "body is not utf-8".to_owned()))?;
    if !form {
        return Ok(text.trim().to_owned());
    }
    text.split('&')
        .find_map(|pair| pair.strip_prefix("p="))
        .and_then(|v| percent_decode_str(v).decode_utf8().ok())
        .map(|v| v.trim().to_owned())
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "no proof in form".to_owned()))
}

fn now() -> Result<u64, Fail> {
    weft_home::now().map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "no clock".to_owned()))
}

fn failed((status, message): Fail) -> Reply {
    html_reply(status, html::error(status.as_u16(), &message))
}

fn with_cookie(mut reply: Reply, cookie: &str) -> Reply {
    if let Ok(v) = HeaderValue::from_str(cookie) {
        reply.headers_mut().insert(SET_COOKIE, v);
    }
    reply
}

fn refused(refusal: &Refusal) -> Reply {
    let status = match refusal {
        Refusal::Proof(_) | Refusal::Nonce | Refusal::Denied => StatusCode::FORBIDDEN,
        Refusal::Full => StatusCode::SERVICE_UNAVAILABLE,
        Refusal::Host => StatusCode::BAD_REQUEST,
        Refusal::Origin | Refusal::Random | Refusal::State(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    html_reply(status, html::error(status.as_u16(), &refusal.to_string()))
}

fn logged_in(logins: &Logins, author: &PublicKey, host: Option<&str>) -> Reply {
    match logins.service(host) {
        Ok(service) => {
            html_reply(StatusCode::OK, html::logged_in(&author.address().to_string(), &service))
        }
        Err(r) => refused(&r),
    }
}

async fn post_login(gateway: &Gateway, text: &str, host: Option<&str>) -> Reply {
    let now = match now() {
        Ok(n) => n,
        Err(f) => return failed(f),
    };
    let proof = match Proof::from_text(text) {
        Ok(p) => p,
        Err(e) => return html_reply(StatusCode::BAD_REQUEST, html::error(400, &e.to_string())),
    };
    let newer = gateway.resolver.freshest_manifest(proof.login.author()).await.ok().flatten();
    match gateway.logins.satisfy(&proof, now, newer.as_ref()) {
        Ok((author, token)) => with_cookie(
            logged_in(&gateway.logins, &author, host),
            &gateway.logins.cookie(Some(&token)),
        ),
        Err(r) => refused(&r),
    }
}

fn login_page(logins: &Logins, token: Option<&Token>, host: Option<&str>) -> Reply {
    let now = match now() {
        Ok(n) => n,
        Err(f) => return failed(f),
    };
    if let Some(author) = token.and_then(|t| logins.session(t, now)) {
        return logged_in(logins, &author, host);
    }
    match logins.open(now, host) {
        Ok(challenge) => {
            let location = format!("/login/{}", text::to_text(&challenge.nonce));
            let mut r = html_reply(StatusCode::SEE_OTHER, html::error(303, &location));
            if let Ok(v) = HeaderValue::from_str(&location) {
                r.headers_mut().insert(LOCATION, v);
            }
            r
        }
        Err(r) => refused(&r),
    }
}

fn claim(logins: &Logins, rest: &str, host: Option<&str>) -> Reply {
    let now = match now() {
        Ok(n) => n,
        Err(f) => return failed(f),
    };
    let nonce: Option<[u8; 32]> = text::from_text(rest).ok().and_then(|b| b.try_into().ok());
    let Some(nonce) = nonce else {
        return html_reply(StatusCode::BAD_REQUEST, html::error(400, "not a challenge"));
    };
    match logins.claim(&nonce, now) {
        Claim::Unknown => refused(&Refusal::Nonce),
        Claim::Waiting(challenge) => html_reply(StatusCode::OK, html::challenge(&challenge)),
        Claim::Ready(token) => match logins.session(&token, now) {
            Some(author) => {
                with_cookie(logged_in(logins, &author, host), &logins.cookie(Some(&token)))
            }
            None => refused(&Refusal::Nonce),
        },
    }
}

fn logout(logins: &Logins, token: Option<&Token>) -> Reply {
    if let Some(Err(r)) = token.map(|t| logins.logout(t)) {
        return refused(&r);
    }
    let mut r = html_reply(StatusCode::SEE_OTHER, html::error(303, "/login"));
    r.headers_mut().insert(LOCATION, HeaderValue::from_static("/login"));
    with_cookie(r, &logins.cookie(None))
}

fn provenance(reply: &mut Reply, page: &Page) {
    for (name, value) in [
        ("x-weft-address", &page.address),
        ("x-weft-author", &page.author),
        ("x-weft-signer", &page.signer),
        ("x-weft-source", &page.source),
        ("x-weft-name", &page.name),
    ] {
        if let Ok(v) = HeaderValue::from_str(value) {
            reply.headers_mut().insert(HeaderName::from_static(name), v);
        }
    }
}

pub fn sniff(data: &[u8]) -> &'static str {
    if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        "image/png"
    } else if data.starts_with(b"\xff\xd8\xff") {
        "image/jpeg"
    } else if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        "image/gif"
    } else if data.len() >= 12 && &data[..4] == b"RIFF" && &data[8..12] == b"WEBP" {
        "image/webp"
    } else {
        "application/octet-stream"
    }
}

fn html_reply(status: StatusCode, body: String) -> Reply {
    reply(status, "text/html; charset=utf-8", body.into())
}

fn reply(status: StatusCode, content_type: &'static str, body: Bytes) -> Reply {
    let mut r = Response::new(Full::new(body));
    *r.status_mut() = status;
    let h = r.headers_mut();
    h.insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    h.insert(CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP));
    h.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    r
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn sniff_knows_images_only() {
        assert_eq!(sniff(b"\x89PNG\r\n\x1a\n...."), "image/png");
        assert_eq!(sniff(b"\xff\xd8\xff\xe0"), "image/jpeg");
        assert_eq!(sniff(b"GIF89a"), "image/gif");
        assert_eq!(sniff(b"RIFF\0\0\0\0WEBPVP8 "), "image/webp");
        assert_eq!(sniff(b"<svg onload=alert(1)>"), "application/octet-stream");
        assert_eq!(sniff(b"<html>"), "application/octet-stream");
        assert_eq!(sniff(b""), "application/octet-stream");
    }

    #[test]
    fn a_publisher_host_is_a_domain_other_than_the_origin() {
        let dir = std::env::temp_dir().join(format!("weft-gateway-{}-host", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let state = Arc::new(State::open(&dir).unwrap());
        let logins = Logins::new("https://gw.example:8443".into(), state, None, 4, 0).unwrap();
        assert_eq!(bare_host("alice.example:80"), "alice.example");
        assert_eq!(bare_host("[::1]:80"), "::1");
        assert_eq!(bare_host("alice.example"), "alice.example");
        assert_eq!(publisher(&logins, None), None);
        assert_eq!(publisher(&logins, Some("gw.example")), None, "the origin is not a publisher");
        assert_eq!(publisher(&logins, Some("gw.example:8443")), None);
        assert_eq!(publisher(&logins, Some("x")), None, "no dot, no domain");
        assert_eq!(publisher(&logins, Some("127.0.0.1:8080")), None, "not a domain");
        assert_eq!(publisher(&logins, Some("alice.example")), Some("alice.example".to_owned()));
        assert_eq!(publisher(&logins, Some("alice.example:443")), Some("alice.example".to_owned()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_path_that_is_not_a_target_falls_under_the_publisher_host() {
        let address = Address::of(b"x").to_string();
        let (t, shown) = target_for("about", Some("alice.example")).unwrap();
        assert_eq!(shown, "alice.example/about");
        assert!(
            matches!(t, Target::Domain { host, name } if host == "alice.example" && name == "about")
        );
        let (t, shown) = target_for(&address, Some("alice.example")).unwrap();
        assert_eq!(shown, address, "a full target keeps its meaning on any host");
        assert!(matches!(t, Target::Address(_)));
        let (t, _) = target_for("bob.example/home", Some("alice.example")).unwrap();
        assert!(matches!(t, Target::Domain { host, .. } if host == "bob.example"));
        assert!(target_for("about", None).is_err());
        assert!(target_for("a/b/c", Some("alice.example")).is_err(), "the original error stands");
        assert!(target_for("", Some("alice.example")).is_err());
    }
}
