use core::fmt::Write as _;

use serde::Serialize;
use tauri::State;
use weft_core::{Address, Petnames, PublicKey, label, petname};
use weft_resolve::{Page, Target};

use crate::marks::Action;
use crate::{App, Result, err};

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
    let petname =
        PublicKey::from_bytes(author.bytes()).ok().and_then(|k| names.name(&k).map(str::to_owned));
    let actions = app.marks.actions().map_err(|e| err(&e))?;
    let local = app.resolver.offline();
    let mut hits = Vec::new();
    for labeler in app.marks.labelers().map_err(|e| err(&e))? {
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
    Ok(View { page, petname, hits, treatment })
}

async fn write(app: &App, names: &Petnames) -> Result<String> {
    let body = names.encode();
    let reads = app.resolver.reads();
    let list = reads
        .call(async |c| c.put(petname::KIND, body.clone(), vec![]).await)
        .await
        .map_err(|e| err(&e))?;
    let pointer =
        reads.call(async |c| c.point(petname::POINTER, list).await).await.map_err(|e| err(&e))?;
    Ok(format!("petnames  {list}\npointer  {}\n", pointer.address()))
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
    labels: Option<usize>,
    error: Option<String>,
}

#[tauri::command]
pub async fn labelers(app: State<'_, App>) -> Result<Vec<Labeler>> {
    let names = own(&app).await.unwrap_or_default();
    let local = app.resolver.offline();
    let mut out = Vec::new();
    for key in app.marks.labelers().map_err(|e| err(&e))? {
        let (labels, error) = match local.labels(key).await {
            Ok(list) => (list.map(|l| l.labels.len()), None),
            Err(e) => (None, Some(e.to_string())),
        };
        out.push(Labeler {
            key: key.address().to_string(),
            petname: names.name(&key).map(str::to_owned),
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
