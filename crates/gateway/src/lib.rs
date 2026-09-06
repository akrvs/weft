#![forbid(unsafe_code)]

pub mod html;
pub mod login;

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::header::{
    ALLOW, CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_SECURITY_POLICY, CONTENT_TYPE, COOKIE,
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
use weft_core::{Address, Proof, PublicKey, login as text};
use weft_resolve::{Error, Links, Page, Resolver, Target};

use crate::login::{Claim, Logins, Refusal, Token, token_from_cookies};

pub const LINKS: Links = Links { record: "/", blob: "/blob/" };
pub const MAX_PATH: usize = 1024;
pub const MAX_BUF: usize = 16 * 1024;
pub const MAX_BODY: usize = text::MAX_PROOF * 4 / 3 + 1024;
pub const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
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

#[derive(Debug)]
pub struct Gateway {
    pub resolver: Resolver,
    pub logins: Logins,
}

impl Gateway {
    pub fn new(resolver: Resolver, origin: String) -> Result<Self, Refusal> {
        Ok(Self { resolver, logins: Logins::new(origin)? })
    }
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
    let path = req.uri().path().to_owned();
    let mut reply = match (req.method(), path.as_str()) {
        (&Method::POST, "/login") => match body(req).await {
            Ok(text) => post_login(&gateway, &text).await,
            Err(f) => failed(f),
        },
        (&Method::POST, "/logout") => logout(&gateway.logins, token.as_ref()),
        (&Method::GET | &Method::HEAD, "/login") => login_page(&gateway.logins, token.as_ref()),
        (&Method::GET | &Method::HEAD, _) if path.starts_with("/login/") => {
            claim(&gateway.logins, &path[7..])
        }
        (&Method::GET | &Method::HEAD, _) => {
            route(&gateway.resolver, &path, req.uri().query()).await
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

async fn route(resolver: &Resolver, path: &str, query: Option<&str>) -> Reply {
    if path.len() > MAX_PATH {
        return html_reply(StatusCode::URI_TOO_LONG, html::error(414, "path too long"));
    }
    match path {
        "/" => html_reply(StatusCode::OK, html::form()),
        "/style.css" => {
            let mut r = reply(StatusCode::OK, "text/css; charset=utf-8", html::STYLE.into());
            r.headers_mut()
                .insert(CACHE_CONTROL, HeaderValue::from_static("public, max-age=86400"));
            r
        }
        "/go" => go(query),
        _ if path.starts_with("/blob/") => blob(resolver, &path[6..]),
        _ => page(resolver, &path[1..]).await,
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

fn blob(resolver: &Resolver, rest: &str) -> Reply {
    let Ok(address) = rest.parse::<Address>() else {
        return html_reply(StatusCode::BAD_REQUEST, html::error(400, "not a blob address"));
    };
    let Some(data) = resolver.blob(&address) else {
        return html_reply(StatusCode::NOT_FOUND, html::error(404, "blob not in the local store"));
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

async fn page(resolver: &Resolver, rest: &str) -> Reply {
    let Ok(input) = percent_decode_str(rest).decode_utf8() else {
        return html_reply(StatusCode::BAD_REQUEST, html::error(400, "path is not utf-8"));
    };
    let target: Target = match input.parse() {
        Ok(t) => t,
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
                Error::Target(_) => StatusCode::BAD_REQUEST,
                Error::NotFound(_) | Error::NoPointer(_) | Error::Dns(_) | Error::Binding(_) => {
                    StatusCode::NOT_FOUND
                }
                Error::Core(_) | Error::Net(_) | Error::Text => StatusCode::BAD_GATEWAY,
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
        Refusal::Proof(_) | Refusal::Nonce => StatusCode::FORBIDDEN,
        Refusal::Full => StatusCode::SERVICE_UNAVAILABLE,
        Refusal::Origin | Refusal::Random => StatusCode::INTERNAL_SERVER_ERROR,
    };
    html_reply(status, html::error(status.as_u16(), &refusal.to_string()))
}

fn logged_in(logins: &Logins, author: &PublicKey) -> Reply {
    html_reply(StatusCode::OK, html::logged_in(&author.address().to_string(), logins.origin()))
}

async fn post_login(gateway: &Gateway, text: &str) -> Reply {
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
        Ok((author, token)) => {
            with_cookie(logged_in(&gateway.logins, &author), &gateway.logins.cookie(Some(&token)))
        }
        Err(r) => refused(&r),
    }
}

fn login_page(logins: &Logins, token: Option<&Token>) -> Reply {
    let now = match now() {
        Ok(n) => n,
        Err(f) => return failed(f),
    };
    if let Some(author) = token.and_then(|t| logins.session(t, now)) {
        return logged_in(logins, &author);
    }
    match logins.open(now) {
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

fn claim(logins: &Logins, rest: &str) -> Reply {
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
            Some(author) => with_cookie(logged_in(logins, &author), &logins.cookie(Some(&token))),
            None => refused(&Refusal::Nonce),
        },
    }
}

fn logout(logins: &Logins, token: Option<&Token>) -> Reply {
    if let Some(t) = token {
        logins.logout(t);
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
    use super::sniff;

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
}
