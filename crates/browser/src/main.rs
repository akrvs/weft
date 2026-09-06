#![forbid(unsafe_code)]

use std::fmt::Write;
use std::sync::Mutex;

use serde::Serialize;
use tauri::webview::WebviewBuilder;
use tauri::{LogicalPosition, LogicalSize, Manager, State, Webview, WebviewUrl, Window};
use weft_core::{Address, Body, Draft, Manifest, Pointer, Revoke, verify};
use weft_home::{Home, Store};
use weft_resolve::{Links, Page, Resolver, Target};
use zeroize::Zeroizing;

const CHROME_HEIGHT: i32 = 88;

struct App {
    resolver: Resolver,
    web: Mutex<Option<Webview>>,
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
    Ok(Identity {
        root: home.root().map_err(|e| err(&e))?.address().to_string(),
        devices: home
            .devices()
            .map_err(|e| err(&e))?
            .into_iter()
            .map(|d| format!("{}  {}", d.public.address(), d.label))
            .collect(),
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
    kinds: Vec<(String, usize)>,
    grants: Vec<GrantView>,
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn store_view(app: State<'_, App>) -> Result<StoreView> {
    let root = app.resolver.home().root().map_err(|e| err(&e))?;
    let records = app.resolver.store().all().map_err(|e| err(&e))?;
    let manifest = Store::manifest(&records, &root);
    let mut kinds: Vec<(String, usize)> = Vec::new();
    for r in records.iter().filter(|r| r.author() == &root && verify(r, manifest.as_ref()).is_ok())
    {
        match kinds.iter_mut().find(|(k, _)| k == r.kind()) {
            Some((_, n)) => *n += 1,
            None => kinds.push((r.kind().to_owned(), 1)),
        }
    }
    kinds.sort_unstable();
    let now = weft_home::now().map_err(|e| err(&e))?;
    let grants = Store::grants(&records, &root, manifest.as_ref(), now)
        .into_iter()
        .map(|(r, g)| GrantView {
            address: r.address().to_string(),
            app: g.app.address().to_string(),
            access: g.access.to_string(),
            kinds: g.kinds.join(","),
            expires: g.expires,
        })
        .collect();
    Ok(StoreView { kinds, grants })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn revoke_grant(
    app: State<'_, App>,
    grant: String,
    device: String,
    passphrase: String,
) -> Result<String> {
    let passphrase = Zeroizing::new(passphrase.into_bytes());
    let home = app.resolver.home();
    let store = app.resolver.store();
    let root = home.root().map_err(|e| err(&e))?;
    let key = home.open(&device, &passphrase).map_err(|e| err(&e))?;
    let grant: Address = grant.parse().map_err(|e| err(&e))?;
    let created = weft_home::now().map_err(|e| err(&e))?;
    let record =
        Revoke { grant }.draft(&root, &key.public(), created).sign(&key).map_err(|e| err(&e))?;
    let manifest = Store::manifest(&store.all().map_err(|e| err(&e))?, &root);
    verify(&record, manifest.as_ref()).map_err(|e| err(&e))?;
    store.put(&record).map_err(|e| err(&e))?;
    Ok(record.address().to_string())
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
    let home = app.resolver.home();
    let store = app.resolver.store();
    let root = home.root().map_err(|e| err(&e))?;
    let key = home.open(&device, &passphrase).map_err(|e| err(&e))?;
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
        let all = store.all().map_err(|e| err(&e))?;
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
        store.put(r).map_err(|e| err(&e))?;
    }
    let relays = home.relays().map_err(|e| err(&e))?;
    let mut report = format!("{}\n", page.address());
    if !relays.is_empty() {
        let client = app.resolver.client().await.map_err(|e| err(&e))?;
        let mut push = records.clone();
        if let Some(m) = app.resolver.local_manifest(&root).map_err(|e| err(&e))? {
            let manifest_record = store
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
    app.resolver.blob(&address)
}

fn main() {
    let home = Home::new(std::env::var_os("WEFT_HOME").map_or_else(Home::default_dir, Into::into));
    let app = App { resolver: Resolver::new(home), web: Mutex::new(None) };
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
            resolve,
            initial,
            identity,
            publish,
            open_web,
            close_web,
            store_view,
            revoke_grant
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
