#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::fmt::Write;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use tauri::webview::WebviewBuilder;
use tauri::{LogicalPosition, LogicalSize, Manager, State, Webview, WebviewUrl, Window};
use weft_core::{Address, Challenge, Grant, login};
use weft_home::Home;
use weft_resolve::{Links, Page, Resolver, Target};
use weft_store::{Local, socket_path};
use zeroize::Zeroizing;

const CHROME_HEIGHT: i32 = 88;
const LOGIN_TIMEOUT: Duration = Duration::from_secs(10);
const START_TIMEOUT: Duration = Duration::from_secs(60);
const START_POLL: Duration = Duration::from_millis(200);
const LOG_BYTES: usize = 16 * 1024;

struct App {
    resolver: Resolver<Local>,
    web: Mutex<Option<Webview>>,
    daemon: Mutex<Option<Child>>,
    log: Arc<Mutex<VecDeque<u8>>>,
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
    let grants = store
        .call(async |c| c.grants().await)
        .await
        .map_err(|e| err(&e))?
        .iter()
        .map(|r| {
            Grant::from_record(r).map(|g| GrantView {
                address: r.address().to_string(),
                app: g.app.address().to_string(),
                access: g.access.to_string(),
                kinds: g.kinds.join(","),
                expires: g.expires,
            })
        })
        .collect::<core::result::Result<Vec<_>, _>>()
        .map_err(|e| err(&e))?;
    Ok(StoreView { kinds, grants })
}

#[tauri::command]
async fn revoke_grant(app: State<'_, App>, grant: String) -> Result<String> {
    let grant: Address = grant.parse().map_err(|e| err(&e))?;
    let revoked = app.resolver.reads().call(async |c| c.revoke(grant).await).await;
    Ok(revoked.map_err(|e| err(&e))?.to_string())
}

#[tauri::command]
async fn publish(app: State<'_, App>, markdown: String, name: String) -> Result<String> {
    let name = name.trim();
    let body = markdown.into_bytes();
    let pointer = (!name.is_empty()).then_some(name);
    let records = app
        .resolver
        .reads()
        .call(async |c| c.publish(body, pointer).await)
        .await
        .map_err(|e| err(&e))?;
    let page = records.first().ok_or("store returned no records")?;
    let mut report = format!("{}\n", page.address());
    let home = app.resolver.home();
    let relays = home.relays().map_err(|e| err(&e))?;
    if !relays.is_empty() {
        let root = home.root().map_err(|e| err(&e))?;
        let client = app.resolver.client().await.map_err(|e| err(&e))?;
        let mut push = records.clone();
        if let Some(manifest) =
            app.resolver.local_manifest_record(&root).await.map_err(|e| err(&e))?
        {
            push.insert(0, manifest);
        }
        for relay in relays {
            let outcome = client.put(relay, &push).await.map_err(|e| err(&e))?;
            let _ = writeln!(
                report,
                "{relay}  stored {}  rejected {}",
                outcome.stored.len(),
                outcome.rejected.len()
            );
            for (_, why) in outcome.rejected {
                let _ = writeln!(report, "  {why}");
            }
        }
    }
    Ok(report)
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
    log_text(&app.log)
}

#[tauri::command]
async fn start_store(app: State<'_, App>, device: String, passphrase: String) -> Result<String> {
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
    let mut child = Command::new(store_binary())
        .arg("serve")
        .arg("--device")
        .arg(&device)
        .arg("--attach")
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
    Ok(format!("store started with device {device}; it stops when the browser closes"))
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
    let _ = rustls::crypto::ring::default_provider().install_default();
    let home = Home::new(std::env::var_os("WEFT_HOME").map_or_else(Home::default_dir, Into::into));
    let reads = Local::new(home.path().to_path_buf());
    let app = App {
        resolver: Resolver::new(home, reads),
        web: Mutex::new(None),
        daemon: Mutex::new(None),
        log: Arc::default(),
    };
    let result = tauri::Builder::default()
        .manage(app)
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
            publish,
            open_web,
            close_web,
            store_view,
            revoke_grant,
            login_prompt,
            login,
            start_store,
            daemon_log
        ])
        .setup(|app| {
            let window = tauri::window::WindowBuilder::new(app, "main")
                .title("weft")
                .inner_size(1100.0, 800.0)
                .build()?;
            let chrome = WebviewBuilder::new("chrome", WebviewUrl::App("index.html".into()));
            let chrome = window.add_child(
                chrome,
                LogicalPosition::new(0.0, 0.0),
                LogicalSize::new(1.0, 1.0),
            )?;
            frame(&chrome)?;
            Ok(())
        })
        .run(tauri::generate_context!());
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
