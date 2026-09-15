#![forbid(unsafe_code)]

mod blobs;
#[cfg(feature = "drive")]
mod drive;
mod marks;
mod register;
#[cfg(target_os = "linux")]
mod theme;

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use data_encoding::HEXLOWER;
use serde::Serialize;
use tauri::webview::WebviewBuilder;
use tauri::{Emitter, LogicalPosition, LogicalSize, Manager, State, Webview, WebviewUrl, Window};
use weft_core::{Address, Challenge, Grant, Payment, Pointer, Receipt, Record, Voucher, login};
use weft_home::{Home, Relay};
use weft_net::node::decode_preimage;
use weft_resolve::{Links, Page, Resolver, Target, render};
use weft_store::{Local, socket_path};
use zeroize::Zeroizing;

use crate::blobs::Sniff;
use crate::marks::Marks;

const CHROME_HEIGHT: i32 = 88;
const LOGIN_TIMEOUT: Duration = Duration::from_secs(10);
const START_TIMEOUT: Duration = Duration::from_secs(60);
const START_POLL: Duration = Duration::from_millis(200);
const LOG_BYTES: usize = 16 * 1024;

const DAY: u64 = 86_400;

struct App {
    resolver: Resolver<Local>,
    marks: Marks,
    web: Mutex<Option<Webview>>,
    daemon: Mutex<Option<Child>>,
    log: Arc<Mutex<VecDeque<u8>>>,
}

#[derive(Serialize, Clone)]
struct Pull {
    address: String,
    done: u64,
    total: Option<u64>,
}

#[derive(Serialize)]
struct Identity {
    root: String,
    devices: Vec<String>,
    labels: Vec<String>,
    relays: Vec<String>,
}

type Result<T> = core::result::Result<T, String>;

fn err(e: &impl ToString) -> String {
    e.to_string()
}

#[tauri::command]
async fn resolve(app: State<'_, App>, input: String) -> Result<Page> {
    let target: Target = input.parse().map_err(|e| err(&e))?;
    app.resolver.resolve(target, &Links::WEFT).await.map_err(|e| err(&e))
}

#[tauri::command]
fn initial() -> Option<String> {
    std::env::args().nth(1)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn identity(app: State<'_, App>) -> Result<Identity> {
    let home = app.resolver.home();
    let devices = home.devices().map_err(|e| err(&e))?;
    Ok(Identity {
        root: home.root().map_err(|e| err(&e))?.address().to_string(),
        devices: devices.iter().map(|d| format!("{}  {}", d.public.address(), d.label)).collect(),
        labels: devices.into_iter().map(|d| d.label).collect(),
        relays: home.relays().map_err(|e| err(&e))?.iter().map(ToString::to_string).collect(),
    })
}

#[derive(Serialize)]
struct GrantView {
    address: String,
    app: String,
    name: Option<String>,
    access: String,
    kinds: String,
    expires: Option<u64>,
}

#[derive(Serialize)]
struct StoreView {
    kinds: Vec<(String, u64)>,
    grants: Vec<GrantView>,
}

#[tauri::command]
async fn store_view(app: State<'_, App>) -> Result<StoreView> {
    let store = app.resolver.reads();
    let kinds = store.call(async |c| c.kinds().await).await.map_err(|e| err(&e))?;
    let records = store.call(async |c| c.grants().await).await.map_err(|e| err(&e))?;
    let mut grants = Vec::with_capacity(records.len());
    for r in &records {
        let g = Grant::from_record(r).map_err(|e| err(&e))?;
        grants.push(GrantView {
            address: r.address().to_string(),
            app: g.app.address().to_string(),
            name: app.resolver.title(&g.app).await,
            access: g.access.to_string(),
            kinds: g.kinds.join(","),
            expires: g.expires,
        });
    }
    Ok(StoreView { kinds, grants })
}

#[tauri::command]
async fn revoke_grant(app: State<'_, App>, grant: String) -> Result<String> {
    let grant: Address = grant.parse().map_err(|e| err(&e))?;
    let revoked = app.resolver.reads().call(async |c| c.revoke(grant).await).await;
    Ok(revoked.map_err(|e| err(&e))?.to_string())
}

#[derive(Serialize)]
struct Preview {
    html: String,
    title: Option<String>,
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn preview(markdown: String) -> Preview {
    Preview { html: render(&markdown, &Links::WEFT), title: weft_resolve::render::title(&markdown) }
}

#[derive(Serialize)]
struct Price {
    relay: String,
    rate: Option<u64>,
    banks: Vec<String>,
    sats: u64,
    error: Option<String>,
}

#[tauri::command]
async fn price(app: State<'_, App>) -> Result<Vec<Price>> {
    let relays = app.resolver.home().relays().map_err(|e| err(&e))?;
    let client = app.resolver.client().await.map_err(|e| err(&e))?;
    let mut out = Vec::with_capacity(relays.len());
    for relay in relays {
        let (rate, banks, sats, error) = match client.price(&relay).await {
            Ok(q) => {
                let banks = q.banks.iter().map(|b| b.address().to_string()).collect();
                (Some(q.rate), banks, q.sats, None)
            }
            Err(e) => (None, Vec::new(), 0, Some(e.to_string())),
        };
        out.push(Price { relay: relay.to_string(), rate, banks, sats, error });
    }
    Ok(out)
}

#[derive(Serialize)]
struct Offer {
    relay: String,
    bolt11: String,
    hash: String,
    cents: u64,
    sats: u64,
    expires: u64,
}

fn check_days(days: u64) -> Result<()> {
    if days == 0 || days > weft_net::relay::MAX_DAYS {
        return Err(format!("days must be 1 to {}", weft_net::relay::MAX_DAYS));
    }
    Ok(())
}

#[tauri::command]
async fn invoice(app: State<'_, App>, markdown: String, days: u64) -> Result<Offer> {
    check_days(days)?;
    let relays = app.resolver.home().relays().map_err(|e| err(&e))?;
    let client = app.resolver.client().await.map_err(|e| err(&e))?;
    for relay in relays {
        let Ok(quote) = client.price(&relay).await else { continue };
        if quote.sats == 0 {
            continue;
        }
        let kib = (markdown.len() as u64).saturating_add(512).div_ceil(1024).saturating_add(1);
        let cents = kib
            .checked_mul(days)
            .and_then(|k| k.checked_mul(quote.rate))
            .ok_or("cost overflows")?
            .max(1);
        let offer = client.invoice(&relay, cents).await.map_err(|e| err(&e))?;
        return Ok(Offer {
            relay: relay.to_string(),
            bolt11: offer.bolt11,
            hash: HEXLOWER.encode(&offer.hash),
            cents,
            sats: cents.saturating_mul(quote.sats),
            expires: offer.expires,
        });
    }
    Err("no configured relay takes lightning".to_owned())
}

async fn with_manifest(app: &App, records: Vec<Record>) -> Result<Vec<Record>> {
    let root = app.resolver.home().root().map_err(|e| err(&e))?;
    let mut push = records;
    if let Some(manifest) = app.resolver.local_manifest_record(&root).await.map_err(|e| err(&e))? {
        push.insert(0, manifest);
    }
    Ok(push)
}

fn outcome_lines(report: &mut String, relay: &Relay, outcome: &weft_net::client::PutOutcome) {
    let _ = writeln!(
        report,
        "{relay}  stored {}  rejected {}",
        outcome.stored.len(),
        outcome.rejected.len()
    );
    for (_, why) in &outcome.rejected {
        let _ = writeln!(report, "  {why}");
    }
}

async fn push_free(app: &App, records: Vec<Record>, report: &mut String) -> Result<()> {
    let relays = app.resolver.home().relays().map_err(|e| err(&e))?;
    if relays.is_empty() {
        return Ok(());
    }
    let push = with_manifest(app, records).await?;
    let client = app.resolver.client().await.map_err(|e| err(&e))?;
    for relay in &relays {
        let outcome = client.put(relay, &push).await.map_err(|e| err(&e))?;
        outcome_lines(report, relay, &outcome);
    }
    Ok(())
}

fn relay_for(app: &App, wanted: Relay) -> Result<Relay> {
    let relays = app.resolver.home().relays().map_err(|e| err(&e))?;
    Ok(relays.into_iter().find(|r| r.id == wanted.id).unwrap_or(wanted))
}

fn payment(app: &App, pay: &str, relay: &str) -> Result<Option<(Relay, Payment)>> {
    if pay.is_empty() {
        return Ok(None);
    }
    if let Ok(preimage) = decode_preimage(pay) {
        if relay.is_empty() {
            return Err("ask for an invoice first, so the relay is known".to_owned());
        }
        let relay = relay_for(app, relay.parse::<Relay>().map_err(|e| err(&e))?)?;
        return Ok(Some((relay, Payment::Preimage(preimage))));
    }
    let voucher = Voucher::from_text(pay).map_err(|e| err(&e))?;
    let relay = relay_for(app, Relay::from_key(&voucher.to).map_err(|e| err(&e))?)?;
    Ok(Some((relay, Payment::Voucher(Box::new(voucher)))))
}

async fn push_paid(
    app: &App,
    records: Vec<Record>,
    relay: Relay,
    payment: Payment,
    days: u64,
    report: &mut String,
) -> Result<()> {
    check_days(days)?;
    let key = weft_core::PublicKey::from_bytes(relay.id.as_bytes()).map_err(|e| err(&e))?;
    let mut paid: Vec<Address> = records.iter().map(Record::address).collect();
    paid.sort_unstable();
    paid.dedup();
    let until = weft_home::now().map_err(|e| err(&e))?.saturating_add(days.saturating_mul(DAY));
    let cents = payment.cents().map_or_else(|| "lightning".to_owned(), |c| format!("{c} cents"));
    let receipt = Receipt { relay: key, records: paid, until, payment };
    receipt.check().map_err(|e| err(&e))?;
    let body = receipt.encode();
    let store = app.resolver.reads();
    let signed = store.call(async |c| c.receipt(body).await).await.map_err(|e| err(&e))?;
    let mut push = with_manifest(app, records).await?;
    push.push(signed.clone());
    let client = app.resolver.client().await.map_err(|e| err(&e))?;
    let outcome = client.put(&relay, &push).await.map_err(|e| err(&e))?;
    outcome_lines(report, &relay, &outcome);
    if outcome.stored.contains(&signed.address()) {
        store.call(async |c| c.keep(&signed).await).await.map_err(|e| err(&e))?;
        let _ = writeln!(report, "receipt {}  {cents} until {until}", signed.address());
        Ok(())
    } else {
        Err(format!("{report}receipt refused, nothing kept"))
    }
}

#[tauri::command]
async fn publish(
    app: State<'_, App>,
    markdown: String,
    name: String,
    pay: String,
    relay: String,
    days: u64,
) -> Result<String> {
    let name = name.trim();
    let paid = payment(&app, pay.trim(), relay.trim())?;
    let body = markdown.into_bytes();
    let pointer = (!name.is_empty()).then_some(name);
    let records = app
        .resolver
        .reads()
        .call(async |c| c.publish(body, pointer).await)
        .await
        .map_err(|e| err(&e))?;
    let mut report = String::new();
    for record in &records {
        let _ = writeln!(report, "{}  {}", record.kind(), record.address());
    }
    match paid {
        Some((relay, payment)) => {
            push_paid(&app, records, relay, payment, days, &mut report).await?;
        }
        None => push_free(&app, records, &mut report).await?,
    }
    Ok(report)
}

#[derive(Serialize)]
struct Head {
    name: String,
    target: String,
    seq: u64,
    address: String,
}

#[tauri::command]
async fn names(app: State<'_, App>) -> Result<Vec<Head>> {
    let records =
        app.resolver.reads().call(async |c| c.names().await).await.map_err(|e| err(&e))?;
    let mut out = Vec::with_capacity(records.len());
    for r in &records {
        let p = Pointer::from_record(r).map_err(|e| err(&e))?;
        out.push(Head {
            name: p.name,
            target: p.target.to_string(),
            seq: p.seq,
            address: r.address().to_string(),
        });
    }
    Ok(out)
}

#[tauri::command]
async fn point(app: State<'_, App>, name: String, target: String) -> Result<String> {
    let target: Address = target.trim().parse().map_err(|e| err(&e))?;
    let name = name.trim().to_owned();
    let pointer = app
        .resolver
        .reads()
        .call(async |c| c.point(&name, target).await)
        .await
        .map_err(|e| err(&e))?;
    let mut report = format!("pointer  {}\n", pointer.address());
    push_free(&app, vec![pointer], &mut report).await?;
    Ok(report)
}

#[derive(Serialize)]
struct BlobView {
    size: u64,
    kind: Sniff,
    text: Option<String>,
}

async fn blob_bytes(app: &App, address: &str) -> Result<(Address, Vec<u8>)> {
    let address: Address = address.trim().parse().map_err(|e| err(&e))?;
    let data = app.resolver.blob(address).await.map_err(|e| err(&e))?.ok_or("blob not found")?;
    Ok((address, data))
}

#[tauri::command]
async fn blob_view(app: State<'_, App>, address: String) -> Result<BlobView> {
    let (_, data) = blob_bytes(&app, &address).await?;
    let kind = blobs::sniff(&data);
    let text = (kind == Sniff::Text).then(|| String::from_utf8_lossy(&data).into_owned());
    Ok(BlobView { size: data.len() as u64, kind, text })
}

#[tauri::command]
async fn save_blob(app: State<'_, App>, address: String) -> Result<String> {
    let (address, data) = blob_bytes(&app, &address).await?;
    let dir = blobs::downloads().map_err(|e| err(&e))?;
    let path = blobs::save(&dir, address, &data).map_err(|e| err(&e))?;
    Ok(path.display().to_string())
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn history(app: State<'_, App>) -> Result<Vec<(u64, String)>> {
    app.marks.history().map_err(|e| err(&e))
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn visit(app: State<'_, App>, target: String) -> Result<()> {
    let now = weft_home::now().map_err(|e| err(&e))?;
    app.marks.visit(&target, now).map_err(|e| err(&e))
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn clear_history(app: State<'_, App>) -> Result<()> {
    app.marks.clear_history().map_err(|e| err(&e))
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn bookmarks(app: State<'_, App>) -> Result<Vec<(String, String)>> {
    app.marks.bookmarks().map_err(|e| err(&e))
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn bookmark(app: State<'_, App>, target: String, title: String) -> Result<()> {
    app.marks.bookmark(&target, title.trim()).map_err(|e| err(&e))
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn unbookmark(app: State<'_, App>, target: String) -> Result<()> {
    app.marks.unbookmark(&target).map_err(|e| err(&e))
}

#[derive(Serialize)]
struct LoginPrompt {
    service: String,
    expires: u64,
    nonce: String,
}

fn service_url(service: &str) -> Result<reqwest::Url> {
    let url: reqwest::Url = format!("{service}/login").parse().map_err(|e| err(&e))?;
    let loopback = url.host_str().is_some_and(|h| matches!(h, "127.0.0.1" | "localhost" | "[::1]"));
    match url.scheme() {
        "https" => Ok(url),
        "http" if loopback => Ok(url),
        _ => Err("service must be https or loopback http".to_owned()),
    }
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn login_prompt(challenge: String) -> Result<LoginPrompt> {
    let c = Challenge::from_text(&challenge).map_err(|e| err(&e))?;
    service_url(&c.service)?;
    let now = weft_home::now().map_err(|e| err(&e))?;
    if now >= c.expires {
        return Err("challenge expired".to_owned());
    }
    Ok(LoginPrompt { service: c.service, expires: c.expires, nonce: login::to_text(&c.nonce) })
}

#[tauri::command]
async fn login(app: State<'_, App>, challenge: String) -> Result<String> {
    let c = Challenge::from_text(&challenge).map_err(|e| err(&e))?;
    let url = service_url(&c.service)?;
    let proof =
        app.resolver.reads().call(async |s| s.login(&c).await).await.map_err(|e| err(&e))?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(LOGIN_TIMEOUT)
        .build()
        .map_err(|e| err(&e))?;
    let response = client
        .post(url)
        .header("content-type", "text/plain")
        .body(proof.to_text())
        .send()
        .await
        .map_err(|e| err(&e))?;
    let status = response.status();
    if status.is_success() {
        Ok(format!("logged in at {} as {}", c.service, proof.login.author().address()))
    } else {
        Err(format!("{} answered {status}", c.service))
    }
}

fn store_binary() -> PathBuf {
    std::env::current_exe()
        .map(|p| p.with_file_name("weft-store"))
        .ok()
        .filter(|p| p.is_file())
        .unwrap_or_else(|| PathBuf::from("weft-store"))
}

fn drain(child: &mut Child, log: &Arc<Mutex<VecDeque<u8>>>) -> Option<std::thread::JoinHandle<()>> {
    let mut stderr = child.stderr.take()?;
    let log = Arc::clone(log);
    Some(std::thread::spawn(move || {
        let mut chunk = [0u8; 1024];
        while let Ok(n) = stderr.read(&mut chunk)
            && n > 0
            && let Ok(mut log) = log.lock()
        {
            log.extend(&chunk[..n]);
            let excess = log.len().saturating_sub(LOG_BYTES);
            log.drain(..excess);
        }
    }))
}

fn log_text(log: &Arc<Mutex<VecDeque<u8>>>) -> String {
    let Ok(mut log) = log.lock() else { return String::new() };
    String::from_utf8_lossy(log.make_contiguous()).trim().to_owned()
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn daemon_log(app: State<'_, App>) -> String {
    let file = weft_store::log::tail(app.resolver.home().path());
    let ring = log_text(&app.log);
    format!("{file}{ring}").trim().to_owned()
}

#[tauri::command]
async fn stop_store(app: State<'_, App>) -> Result<String> {
    let home = app.resolver.home().path().to_path_buf();
    let key = weft_store::browser_key(&home).map_err(|e| err(&e))?;
    let mut client = weft_store::Client::connect(&weft_store::socket_path(&home), &key)
        .await
        .map_err(|e| err(&e))?;
    client.stop().await.map_err(|e| err(&e))?;
    Ok("stopped".to_owned())
}

#[tauri::command]
async fn start_store(
    app: State<'_, App>,
    device: String,
    passphrase: String,
    detach: bool,
) -> Result<String> {
    let passphrase = Zeroizing::new(passphrase);
    if passphrase.is_empty() || passphrase.contains(['\r', '\n']) {
        return Err("passphrase must be one non-empty line".to_owned());
    }
    {
        let mut slot = app.daemon.lock().map_err(|e| err(&e))?;
        if let Some(child) = slot.as_mut() {
            match child.try_wait() {
                Ok(None) => return Err("the store is already started from here".to_owned()),
                _ => *slot = None,
            }
        }
    }
    let home = app.resolver.home().path();
    let mut command = Command::new(store_binary());
    command.arg("serve").arg("--device").arg(&device);
    if detach {
        command.process_group(0);
    } else {
        command.arg("--attach");
    }
    let mut child = command
        .env("WEFT_HOME", home)
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot start weft-store: {e}"))?;
    if let Ok(mut log) = app.log.lock() {
        log.clear();
    }
    let reader = drain(&mut child, &app.log);
    if let Some(stdin) = child.stdin.as_mut() {
        let mut line = Zeroizing::new(passphrase.as_bytes().to_vec());
        line.push(b'\n');
        std::io::Write::write_all(stdin, &line).map_err(|e| err(&e))?;
        std::io::Write::flush(stdin).map_err(|e| err(&e))?;
    }
    if detach {
        drop(child.stdin.take());
    }
    let socket = socket_path(home);
    let deadline = std::time::Instant::now() + START_TIMEOUT;
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            if let Some(reader) = reader {
                let _ = reader.join();
            }
            let why = log_text(&app.log);
            return Err(if why.is_empty() { format!("weft-store exited: {status}") } else { why });
        }
        if tokio::net::UnixStream::connect(&socket).await.is_ok() {
            break;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            return Err("weft-store did not open its socket in time".to_owned());
        }
        tokio::time::sleep(START_POLL).await;
    }
    *app.daemon.lock().map_err(|e| err(&e))? = Some(child);
    Ok(if detach {
        format!("store started with device {device}; it keeps running after the browser closes")
    } else {
        format!("store started with device {device}; it stops when the browser closes")
    })
}

fn frame(chrome: &Webview) -> Result<()> {
    chrome
        .with_webview(|platform| {
            use gtk::prelude::*;
            let widget = platform.inner();
            let Some(vbox) = widget.parent().and_then(|p| p.downcast::<gtk::Box>().ok()) else {
                return;
            };
            vbox.remove(&widget);
            let frame = gtk::ScrolledWindow::builder()
                .hscrollbar_policy(gtk::PolicyType::External)
                .vscrollbar_policy(gtk::PolicyType::External)
                .build();
            frame.add(&widget);
            vbox.pack_start(&frame, true, true, 0);
            vbox.reorder_child(&frame, 0);
            frame.show_all();
        })
        .map_err(|e| err(&e))
}

fn pack(chrome: &Webview, fixed: bool) -> Result<()> {
    chrome
        .with_webview(move |platform| {
            use gtk::prelude::*;
            let Some(frame) = platform.inner().ancestor(gtk::ScrolledWindow::static_type()) else {
                return;
            };
            if let Some(vbox) = frame.parent().and_then(|p| p.downcast::<gtk::Box>().ok()) {
                vbox.set_child_packing(&frame, !fixed, true, 0, gtk::PackType::Start);
            }
            frame.set_size_request(-1, if fixed { CHROME_HEIGHT } else { -1 });
        })
        .map_err(|e| err(&e))
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn open_web(app: State<'_, App>, window: Window, url: String) -> Result<()> {
    let url: tauri::Url = url.parse().map_err(|e| err(&e))?;
    if url.scheme() != "https" {
        return Err("only https pages open in the web view".to_owned());
    }
    let mut guard = app.web.lock().map_err(|e| err(&e))?;
    if let Some(existing) = guard.as_ref() {
        existing.navigate(url).map_err(|e| err(&e))?;
        return Ok(());
    }
    let chrome = window.get_webview("chrome").ok_or("chrome web view missing")?;
    pack(&chrome, true)?;
    let builder = WebviewBuilder::new("web", WebviewUrl::External(url))
        .on_navigation(|u| u.scheme() == "https")
        .incognito(true);
    let webview = window
        .add_child(builder, LogicalPosition::new(0.0, 0.0), LogicalSize::new(1.0, 1.0))
        .map_err(|e| err(&e))?;
    *guard = Some(webview);
    Ok(())
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn close_web(app: State<'_, App>, window: Window) -> Result<()> {
    if let Some(webview) = app.web.lock().map_err(|e| err(&e))?.take() {
        webview.close().map_err(|e| err(&e))?;
        let chrome = window.get_webview("chrome").ok_or("chrome web view missing")?;
        pack(&chrome, false)?;
    }
    Ok(())
}

async fn blob(app: &App, path: &str) -> Option<Vec<u8>> {
    let address: Address = path.rsplit('/').next()?.parse().ok()?;
    app.resolver.blob(address).await.ok().flatten()
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("register") {
        let code = match register::register() {
            Ok(path) => {
                let _ = writeln!(std::io::stdout(), "weft: links open here, {}", path.display());
                0
            }
            Err(e) => {
                let _ = writeln!(std::io::stderr(), "error: {e}");
                1
            }
        };
        std::process::exit(code);
    }
    let _ = rustls::crypto::ring::default_provider().install_default();
    let home = Home::new(std::env::var_os("WEFT_HOME").map_or_else(Home::default_dir, Into::into));
    let result = tauri::Builder::default()
        .register_asynchronous_uri_scheme_protocol("weft", |ctx, request, responder| {
            let handle = ctx.app_handle().clone();
            let path = request.uri().path().to_owned();
            tauri::async_runtime::spawn(async move {
                let response = match blob(&handle.state::<App>(), &path).await {
                    Some(data) => tauri::http::Response::builder()
                        .header("content-type", "application/octet-stream")
                        .body(data)
                        .unwrap_or_default(),
                    None => tauri::http::Response::builder()
                        .status(404)
                        .body(Vec::new())
                        .unwrap_or_default(),
                };
                responder.respond(response);
            });
        })
        .invoke_handler(tauri::generate_handler![
            resolve,
            initial,
            identity,
            preview,
            price,
            invoice,
            publish,
            names,
            point,
            blob_view,
            save_blob,
            history,
            visit,
            clear_history,
            bookmarks,
            bookmark,
            unbookmark,
            open_web,
            close_web,
            store_view,
            revoke_grant,
            login_prompt,
            login,
            start_store,
            stop_store,
            daemon_log
        ])
        .setup(move |app| setup(app, home))
        .run(tauri::generate_context!());
    if let Err(e) = result {
        let _ = writeln!(std::io::stderr(), "error: {e}");
        std::process::exit(1);
    }
}

fn setup(app: &tauri::App, home: Home) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let handle = app.handle().clone();
    let watch = move |address: Address, done: u64, total: Option<u64>| {
        let _ = handle.emit("pull", Pull { address: address.to_string(), done, total });
    };
    let reads = Local::new(home.path().to_path_buf());
    let marks = Marks::new(home.path());
    let resolver = Resolver::new(home, reads).watched(Arc::new(watch));
    app.manage(App {
        resolver,
        marks,
        web: Mutex::new(None),
        daemon: Mutex::new(None),
        log: Arc::default(),
    });
    let window = tauri::window::WindowBuilder::new(app, "main")
        .title("weft")
        .inner_size(1100.0, 800.0)
        .build()?;
    let chrome = WebviewBuilder::new("chrome", WebviewUrl::App("index.html".into()));
    #[cfg(target_os = "linux")]
    let source = theme::source();
    #[cfg(target_os = "linux")]
    let chrome =
        chrome.initialization_script(theme::script(source.as_ref().and_then(theme::current)));
    let chrome =
        window.add_child(chrome, LogicalPosition::new(0.0, 0.0), LogicalSize::new(1.0, 1.0))?;
    frame(&chrome)?;
    #[cfg(target_os = "linux")]
    theme::watch(&chrome, source);
    #[cfg(feature = "drive")]
    if let Some(path) = std::env::var_os("WEFT_DRIVE") {
        drive::start(app.handle().clone(), path.as_ref())?;
    }
    Ok(())
}
