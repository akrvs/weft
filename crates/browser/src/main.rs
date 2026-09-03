#![forbid(unsafe_code)]

mod render;

use std::fmt::Write;
use std::sync::Mutex;
use std::time::Duration;

use serde::Serialize;
use tauri::webview::WebviewBuilder;
use tauri::{LogicalPosition, LogicalSize, Manager, State, Webview, WebviewUrl, Window};
use tokio::sync::OnceCell;
use tokio::time::timeout;
use weft_core::{Address, Body, Draft, Manifest, Pointer, PublicKey, Record, verify};
use weft_home::{Home, Store};
use weft_net::Client;
use zeroize::Zeroizing;

const CHROME_HEIGHT: i32 = 88;
const RELAY_TIMEOUT: Duration = Duration::from_secs(5);

struct App {
    home: Home,
    store: Store,
    client: OnceCell<Client>,
    web: Mutex<Option<Webview>>,
}

#[derive(Serialize)]
struct Page {
    address: String,
    kind: String,
    author: String,
    signer: String,
    created: u64,
    source: String,
    html: String,
    blob: Option<String>,
}

#[derive(Serialize)]
struct Identity {
    root: String,
    devices: Vec<String>,
    relays: Vec<String>,
}

type Result<T> = core::result::Result<T, String>;

fn err(e: &impl ToString) -> String {
    e.to_string()
}

impl App {
    async fn client(&self) -> Result<&Client> {
        self.client.get_or_try_init(|| async { Client::bind().await.map_err(|e| err(&e)) }).await
    }

    fn local_manifest(&self, author: &PublicKey) -> Result<Option<Manifest>> {
        Ok(Store::manifest(&self.store.all().map_err(|e| err(&e))?, author))
    }

    async fn manifest(&self, author: &PublicKey) -> Result<Option<Manifest>> {
        if let Some(m) = self.local_manifest(author)? {
            return Ok(Some(m));
        }
        let client = self.client().await?;
        for relay in self.home.relays().map_err(|e| err(&e))? {
            let head = client
                .head(relay, *author, weft_core::pointer::MANIFEST)
                .await
                .map_err(|e| err(&e))?;
            if let Some(record) = head.manifest {
                verify(&record, None).map_err(|e| err(&e))?;
                self.store.put(&record).map_err(|e| err(&e))?;
                return Ok(Some(Manifest::from_record(&record).map_err(|e| err(&e))?));
            }
        }
        Ok(None)
    }

    async fn record(&self, address: Address) -> Result<(Record, String)> {
        if let Some(record) =
            self.store.all().map_err(|e| err(&e))?.into_iter().find(|r| r.address() == address)
        {
            return Ok((record, "local store".to_owned()));
        }
        let client = self.client().await?;
        for relay in self.home.relays().map_err(|e| err(&e))? {
            if let Ok(Ok(Some(record))) = timeout(RELAY_TIMEOUT, client.get(relay, address)).await {
                return Ok((record, relay.to_string()));
            }
        }
        Err(format!("{address} not found locally or on any relay"))
    }

    async fn head(&self, author: PublicKey, name: &str) -> Result<Address> {
        let manifest = self.manifest(&author).await?;
        let client = self.client().await?;
        let mut best: Option<(Record, Pointer)> = None;
        for relay in self.home.relays().map_err(|e| err(&e))? {
            let Ok(Ok(head)) = timeout(RELAY_TIMEOUT, client.head(relay, author, name)).await
            else {
                continue;
            };
            let Some(record) = head.pointer else { continue };
            if record.author() != &author || verify(&record, manifest.as_ref()).is_err() {
                continue;
            }
            let pointer = Pointer::from_record(&record).map_err(|e| err(&e))?;
            if pointer.name != name {
                continue;
            }
            if best
                .as_ref()
                .is_none_or(|(r, p)| Pointer::compare((&record, &pointer), (r, p)).is_gt())
            {
                best = Some((record, pointer));
            }
        }
        let records = self.store.all().map_err(|e| err(&e))?;
        let local = Store::pointers(&records, &author, name, manifest.as_ref());
        if let Some((r, p)) = Store::head(&local)
            && best.as_ref().is_none_or(|(br, bp)| Pointer::compare((r, p), (br, bp)).is_gt())
        {
            best = Some((r.clone(), p.clone()));
        }
        let (record, pointer) = best.ok_or_else(|| format!("no valid pointer named {name}"))?;
        self.store.put(&record).map_err(|e| err(&e))?;
        Ok(pointer.target)
    }

    async fn open(&self, address: Address) -> Result<Page> {
        let (record, source) = self.record(address).await?;
        let manifest =
            if record.self_signed() { None } else { self.manifest(record.author()).await? };
        let verified = verify(&record, manifest.as_ref()).map_err(|e| err(&e))?;
        self.store.put(&record).map_err(|e| err(&e))?;
        let (html, blob) = match record.body() {
            Body::Inline(bytes) if record.kind() == "page" => {
                (render::render(core::str::from_utf8(bytes).map_err(|e| err(&e))?), None)
            }
            Body::Inline(bytes) => {
                let mut s = String::from("<pre>");
                s.push_str(&render::render(&format!(
                    "```\n{}\n```",
                    String::from_utf8_lossy(bytes)
                )));
                s.push_str("</pre>");
                (s, None)
            }
            Body::Blob(blob) => (String::new(), Some(blob.to_string())),
        };
        Ok(Page {
            address: verified.address.to_string(),
            kind: verified.kind,
            author: verified.author.to_string(),
            signer: verified.signer.to_string(),
            created: record.created(),
            source,
            html,
            blob,
        })
    }
}

#[tauri::command]
async fn resolve(app: State<'_, App>, input: String) -> Result<Page> {
    let input = input.trim();
    let address = match input.split_once('/') {
        Some((author, name)) => {
            let author: Address = author.parse().map_err(|e| err(&e))?;
            app.head(PublicKey::from_bytes(author.bytes()).map_err(|e| err(&e))?, name.trim())
                .await?
        }
        None => input.parse().map_err(|e| err(&e))?,
    };
    app.open(address).await
}

#[tauri::command]
fn initial() -> Option<String> {
    std::env::args().nth(1)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn identity(app: State<'_, App>) -> Result<Identity> {
    Ok(Identity {
        root: app.home.root().map_err(|e| err(&e))?.address().to_string(),
        devices: app
            .home
            .devices()
            .map_err(|e| err(&e))?
            .into_iter()
            .map(|d| format!("{}  {}", d.public.address(), d.label))
            .collect(),
        relays: app.home.relays().map_err(|e| err(&e))?.iter().map(ToString::to_string).collect(),
    })
}

#[tauri::command]
async fn publish(
    app: State<'_, App>,
    markdown: String,
    name: String,
    device: String,
    passphrase: String,
) -> Result<String> {
    let passphrase = Zeroizing::new(passphrase.into_bytes());
    let root = app.home.root().map_err(|e| err(&e))?;
    let key = app.home.open(&device, &passphrase).map_err(|e| err(&e))?;
    let created = weft_home::now().map_err(|e| err(&e))?;
    let page = Draft {
        author: root,
        signer: key.public(),
        kind: "page".to_owned(),
        created,
        refs: vec![],
        body: Body::Inline(markdown.into_bytes()),
    }
    .sign(&key)
    .map_err(|e| err(&e))?;
    let mut records = vec![page.clone()];
    if !name.trim().is_empty() {
        let all = app.store.all().map_err(|e| err(&e))?;
        let manifest = Store::manifest(&all, &root);
        let existing = Store::pointers(&all, &root, name.trim(), manifest.as_ref());
        let seq = existing.iter().map(|(_, p)| p.seq).max().map_or(1, |s| s.saturating_add(1));
        let prev = Store::head(&existing).map(|(r, _)| r.address()).into_iter().collect();
        let pointer = Pointer { name: name.trim().to_owned(), target: page.address(), seq, prev };
        let record =
            pointer.draft(&root, &key.public(), created).sign(&key).map_err(|e| err(&e))?;
        verify(&record, manifest.as_ref()).map_err(|e| err(&e))?;
        records.push(record);
    }
    for r in &records {
        app.store.put(r).map_err(|e| err(&e))?;
    }
    let relays = app.home.relays().map_err(|e| err(&e))?;
    let mut report = format!("{}\n", page.address());
    if !relays.is_empty() {
        let client = app.client().await?;
        let mut push = records.clone();
        if let Some(m) = app.local_manifest(&root)? {
            let manifest_record = app
                .store
                .all()
                .map_err(|e| err(&e))?
                .into_iter()
                .find(|r| Manifest::from_record(r).is_ok_and(|x| x.seq == m.seq));
            if let Some(mr) = manifest_record {
                push.insert(0, mr);
            }
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

fn blob(app: &App, path: &str) -> Option<Vec<u8>> {
    let address: Address = path.rsplit('/').next()?.parse().ok()?;
    let data = std::fs::read(app.home.blob_path(&address)).ok()?;
    (Address::of(&data) == address).then_some(data)
}

fn main() {
    let home = Home::new(std::env::var_os("WEFT_HOME").map_or_else(Home::default_dir, Into::into));
    let store = home.store();
    let app = App { home, store, client: OnceCell::new(), web: Mutex::new(None) };
    let result = tauri::Builder::default()
        .manage(app)
        .register_uri_scheme_protocol("weft", |ctx, request| {
            let body = blob(&ctx.app_handle().state::<App>(), request.uri().path());
            match body {
                Some(data) => tauri::http::Response::builder()
                    .header("content-type", "application/octet-stream")
                    .body(data)
                    .unwrap_or_default(),
                None => tauri::http::Response::builder()
                    .status(404)
                    .body(Vec::new())
                    .unwrap_or_default(),
            }
        })
        .invoke_handler(tauri::generate_handler![
            resolve, initial, identity, publish, open_web, close_web
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
