use core::fmt::Write as _;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;
use tauri::State;
use weft_core::{Address, Follows, Petnames, PublicKey, follow, label, petname};
use weft_resolve::{Page, Target, Trust};

use crate::marks::{Action, Reach};
use crate::{App, Result, err};

pub const TRUST_TTL: Duration = Duration::from_secs(60);

#[derive(Debug, Default)]
pub struct Cache(Mutex<Option<(Instant, Arc<Trust>)>>);

impl Cache {
    fn get(&self) -> Option<Arc<Trust>> {
        let slot = self.0.lock().ok()?;
        slot.as_ref().filter(|(at, _)| at.elapsed() < TRUST_TTL).map(|(_, t)| Arc::clone(t))
    }

    fn put(&self, trust: Arc<Trust>) {
        if let Ok(mut slot) = self.0.lock() {
            *slot = Some((Instant::now(), trust));
        }
    }

    fn clear(&self) {
        if let Ok(mut slot) = self.0.lock() {
            *slot = None;
        }
    }
}

async fn trust(app: &App) -> Option<Arc<Trust>> {
    if let Some(trust) = app.trust.get() {
        return Some(trust);
    }
    let root = app.resolver.home().root().ok()?;
    let trust = Arc::new(app.resolver.offline().trust(root).await.ok()?);
    app.trust.put(Arc::clone(&trust));
    Some(trust)
}

fn hops(trust: Option<&Trust>, key: &PublicKey) -> Option<u8> {
    trust.and_then(|t| t.distance(key))
}

#[derive(Serialize)]
pub struct Hit {
    value: String,
    labeler: String,
    by: Option<String>,
    action: Option<Action>,
}

#[derive(Serialize)]
pub struct View {
    #[serde(flatten)]
    page: Page,
    petname: Option<String>,
    distance: Option<u8>,
    followed: bool,
    hits: Vec<Hit>,
    treatment: Option<Action>,
}

fn key_of(text: &str) -> Result<PublicKey> {
    let address: Address = text.trim().parse().map_err(|e| err(&e))?;
    if address.kind() != weft_core::address::Kind::Key {
        return Err(format!("{address} is not a key address"));
    }
    PublicKey::from_bytes(address.bytes()).map_err(|e| err(&e))
}

async fn own(app: &App) -> Result<Petnames> {
    app.resolver.petnames().await.map_err(|e| err(&e))
}

async fn key_or_petname(app: &App, text: &str) -> Result<PublicKey> {
    match text.trim().parse::<Target>() {
        Ok(Target::Petname { petname, .. }) => {
            own(app).await?.key(&petname).ok_or_else(|| format!("no petname {petname}"))
        }
        _ => key_of(text),
    }
}

pub async fn annotate(app: &App, page: Page) -> Result<View> {
    let names = app.resolver.petnames().await.unwrap_or_default();
    let record: Address = page.address.parse().map_err(|e| err(&e))?;
    let author: Address = page.author.parse().map_err(|e| err(&e))?;
    let key = PublicKey::from_bytes(author.bytes()).map_err(|e| err(&e))?;
    let petname = names.name(&key).map(str::to_owned);
    let actions = app.marks.actions().map_err(|e| err(&e))?;
    let reach = app.marks.reach().map_err(|e| err(&e))?;
    let trust = trust(app).await;
    let distance = hops(trust.as_deref(), &key);
    let followed = own_follows(app).await.is_ok_and(|f| f.contains(&key));
    let local = app.resolver.offline();
    let mut hits = Vec::new();
    for labeler in app.marks.labelers().map_err(|e| err(&e))? {
        if !reach.admits(hops(trust.as_deref(), &labeler)) {
            continue;
        }
        let Ok(Some(labels)) = local.labels(labeler).await else { continue };
        for value in labels.on(&record, &author) {
            hits.push(Hit {
                value: value.to_owned(),
                labeler: labeler.address().to_string(),
                by: names.name(&labeler).map(str::to_owned),
                action: actions.iter().find(|(v, _)| v == value).map(|(_, a)| *a),
            });
        }
    }
    let treatment = hits.iter().filter_map(|h| h.action).max();
    Ok(View { page, petname, distance, followed, hits, treatment })
}

async fn put(app: &App, kind: &str, pointer: &str, body: Vec<u8>) -> Result<String> {
    let reads = app.resolver.reads();
    let list =
        reads.call(async |c| c.put(kind, body.clone(), vec![]).await).await.map_err(|e| err(&e))?;
    let head = reads.call(async |c| c.point(pointer, list).await).await.map_err(|e| err(&e))?;
    Ok(format!("{pointer}  {list}\npointer  {}\n", head.address()))
}

async fn write(app: &App, names: &Petnames) -> Result<String> {
    put(app, petname::KIND, petname::POINTER, names.encode()).await
}

#[tauri::command]
pub async fn petnames(app: State<'_, App>) -> Result<Vec<(String, String)>> {
    Ok(own(&app).await?.names.into_iter().map(|p| (p.name, p.key.address().to_string())).collect())
}

#[tauri::command]
pub async fn add_petname(app: State<'_, App>, name: String, key: String) -> Result<String> {
    let key = key_of(&key)?;
    let name = name.trim();
    let mut names = own(&app).await?;
    if let Some(held) = names.key(name) {
        return Err(format!("{name} already names {}", held.address()));
    }
    names.insert(name, key).map_err(|e| err(&e))?;
    write(&app, &names).await
}

#[tauri::command]
pub async fn remove_petname(app: State<'_, App>, name: String) -> Result<String> {
    let mut names = own(&app).await?;
    if !names.remove(&name) {
        return Err(format!("no petname {name}"));
    }
    write(&app, &names).await
}

#[tauri::command]
pub async fn import_petnames(app: State<'_, App>, key: String) -> Result<String> {
    let from = key_or_petname(&app, &key).await?;
    let theirs = app
        .resolver
        .petnames_of(from)
        .await
        .map_err(|e| err(&e))?
        .ok_or_else(|| format!("{} publishes no petnames", from.address()))?;
    let mut names = own(&app).await?;
    let mut report = String::new();
    let mut added = 0usize;
    for p in &theirs.names {
        if names.insert(&p.name, p.key).map_err(|e| err(&e))? {
            added += 1;
            let _ = writeln!(report, "added  {}  {}", p.name, p.key.address());
        } else {
            let _ = writeln!(report, "kept   {}  already yours", p.name);
        }
    }
    if added > 0 {
        report.push_str(&write(&app, &names).await?);
    }
    Ok(report)
}

#[derive(Serialize)]
pub struct Labeler {
    key: String,
    petname: Option<String>,
    distance: Option<u8>,
    reach: bool,
    labels: Option<usize>,
    error: Option<String>,
}

#[tauri::command]
pub async fn labelers(app: State<'_, App>) -> Result<Vec<Labeler>> {
    let names = own(&app).await.unwrap_or_default();
    let reach = app.marks.reach().map_err(|e| err(&e))?;
    let trust = trust(&app).await;
    let local = app.resolver.offline();
    let mut out = Vec::new();
    for key in app.marks.labelers().map_err(|e| err(&e))? {
        let distance = hops(trust.as_deref(), &key);
        let (labels, error) = match local.labels(key).await {
            Ok(list) => (list.map(|l| l.labels.len()), None),
            Err(e) => (None, Some(e.to_string())),
        };
        out.push(Labeler {
            key: key.address().to_string(),
            petname: names.name(&key).map(str::to_owned),
            distance,
            reach: reach.admits(distance),
            labels,
            error,
        });
    }
    Ok(out)
}

async fn pull(app: &App, key: PublicKey) -> String {
    match app.resolver.labels(key).await {
        Ok(Some(list)) => format!("{}  {} labels", key.address(), list.labels.len()),
        Ok(None) => format!("{}  no {} pointer yet", key.address(), label::POINTER),
        Err(e) => format!("{}  {e}", key.address()),
    }
}

#[tauri::command]
pub async fn subscribe(app: State<'_, App>, labeler: String) -> Result<String> {
    let key = key_or_petname(&app, &labeler).await?;
    app.marks.subscribe(&key).map_err(|e| err(&e))?;
    Ok(pull(&app, key).await)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn unsubscribe(app: State<'_, App>, labeler: String) -> Result<()> {
    app.marks.unsubscribe(&key_of(&labeler)?).map_err(|e| err(&e))
}

#[tauri::command]
pub async fn refresh_labels(app: State<'_, App>) -> Result<String> {
    let mut report = String::new();
    for key in app.marks.labelers().map_err(|e| err(&e))? {
        let _ = writeln!(report, "{}", pull(&app, key).await);
    }
    Ok(report)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn actions(app: State<'_, App>) -> Result<Vec<(String, Action)>> {
    app.marks.actions().map_err(|e| err(&e))
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn set_action(app: State<'_, App>, value: String, action: String) -> Result<()> {
    let action = match action.as_str() {
        "" | "none" => None,
        other => Some(Action::parse(other).ok_or_else(|| format!("unknown action {other}"))?),
    };
    app.marks.set_action(value.trim(), action).map_err(|e| err(&e))
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn reach(app: State<'_, App>) -> Result<Reach> {
    app.marks.reach().map_err(|e| err(&e))
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn set_reach(app: State<'_, App>, reach: String) -> Result<()> {
    let reach = Reach::parse(reach.trim()).ok_or_else(|| format!("unknown reach {reach}"))?;
    app.marks.set_reach(reach).map_err(|e| err(&e))
}

async fn own_follows(app: &App) -> Result<Follows> {
    if !app.resolver.home().exists() {
        return Ok(Follows::default());
    }
    let root = app.resolver.home().root().map_err(|e| err(&e))?;
    let list = app.resolver.offline().follows_of(root).await.map_err(|e| err(&e))?;
    Ok(list.unwrap_or_default())
}

async fn write_follows(app: &App, follows: &Follows) -> Result<String> {
    app.trust.clear();
    put(app, follow::KIND, follow::POINTER, follows.encode()).await
}

#[derive(Serialize)]
pub struct Followed {
    key: String,
    petname: Option<String>,
}

#[tauri::command]
pub async fn follows(app: State<'_, App>) -> Result<Vec<Followed>> {
    let names = own(&app).await.unwrap_or_default();
    Ok(own_follows(&app)
        .await?
        .keys
        .iter()
        .map(|k| Followed {
            key: k.address().to_string(),
            petname: names.name(k).map(str::to_owned),
        })
        .collect())
}

#[tauri::command]
pub async fn follow(app: State<'_, App>, key: String) -> Result<String> {
    let key = key_or_petname(&app, &key).await?;
    let mut follows = own_follows(&app).await?;
    if !follows.insert(key).map_err(|e| err(&e))? {
        return Err(format!("{} is already followed", key.address()));
    }
    let mut report = write_follows(&app, &follows).await?;
    let pulled = match app.resolver.follows_of(key).await {
        Ok(Some(list)) => format!("{}  follows {}", key.address(), list.keys.len()),
        Ok(None) => format!("{}  no {} pointer yet", key.address(), follow::POINTER),
        Err(e) => format!("{}  {e}", key.address()),
    };
    let _ = writeln!(report, "{pulled}");
    Ok(report)
}

#[tauri::command]
pub async fn unfollow(app: State<'_, App>, key: String) -> Result<String> {
    let key = key_or_petname(&app, &key).await?;
    let mut follows = own_follows(&app).await?;
    if !follows.remove(&key) {
        return Err(format!("{} is not followed", key.address()));
    }
    write_follows(&app, &follows).await
}

#[tauri::command]
pub async fn import_follows(app: State<'_, App>, key: String) -> Result<String> {
    let from = key_or_petname(&app, &key).await?;
    let theirs = app
        .resolver
        .follows_of(from)
        .await
        .map_err(|e| err(&e))?
        .ok_or_else(|| format!("{} publishes no follows", from.address()))?;
    let mut follows = own_follows(&app).await?;
    let mut report = String::new();
    for key in &theirs.keys {
        if follows.insert(*key).map_err(|e| err(&e))? {
            let _ = writeln!(report, "added  {}", key.address());
        }
    }
    if report.is_empty() {
        return Ok("nothing new\n".to_owned());
    }
    report.push_str(&write_follows(&app, &follows).await?);
    Ok(report)
}

#[tauri::command]
pub async fn refresh_trust(app: State<'_, App>) -> Result<String> {
    app.trust.clear();
    let root = app.resolver.home().root().map_err(|e| err(&e))?;
    let trust = app.resolver.trust(root).await.map_err(|e| err(&e))?;
    let mut report = String::new();
    for (distance, count) in trust.counts().iter().enumerate() {
        let _ = writeln!(report, "{distance}  {count}");
    }
    let _ = writeln!(report, "lists  {}", trust.lists());
    app.trust.put(Arc::new(trust));
    Ok(report)
}
