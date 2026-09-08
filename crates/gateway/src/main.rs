#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use tokio::net::TcpListener;
use tokio::signal::unix::{SignalKind, signal};
use weft_core::PublicKey;
use weft_gateway::login::allowlist;
use weft_gateway::{Gateway, budget};
use weft_home::Home;
use weft_resolve::Resolver;
use weft_store::Local;

#[derive(Parser, Debug)]
#[command(name = "weft-gateway", version, about = "Serve signed records over plain HTTP")]
struct Cli {
    #[arg(long, env = "WEFT_HOME")]
    home: Option<PathBuf>,
    #[arg(long, env = "WEFT_GATEWAY_BIND", default_value = "127.0.0.1:8080")]
    bind: SocketAddr,
    #[arg(long, env = "WEFT_GATEWAY_ORIGIN")]
    origin: Option<String>,
    #[arg(long, env = "WEFT_GATEWAY_ALLOW")]
    allow: Option<PathBuf>,
    #[arg(long, env = "WEFT_GATEWAY_PULLS", default_value_t = weft_gateway::MAX_PULLS)]
    pulls: usize,
    #[arg(long, env = "WEFT_GATEWAY_BUDGET", default_value_t = budget::DEFAULT_BYTES / MIB)]
    budget: u64,
}

const MIB: u64 = 1024 * 1024;

fn reload(gateway: &Gateway, allow: Option<&PathBuf>) {
    match allowed(allow) {
        Ok(Some(set)) => {
            eprintln!("reload: allow list has {} identities", set.len());
            gateway.logins.set_allow(Some(set));
        }
        Ok(None) => {}
        Err(e) => eprintln!("reload: allow {e}, keeping the old list"),
    }
    let swept = weft_home::now()
        .map_err(|e| e.to_string())
        .and_then(|now| gateway.logins.sweep(now).map_err(|e| e.to_string()));
    match swept {
        Ok(n) => eprintln!("reload: swept {n} expired sessions"),
        Err(e) => eprintln!("reload: sessions {e}"),
    }
}

async fn on_hangup(gateway: Arc<Gateway>, allow: Option<PathBuf>) {
    let Ok(mut hangup) = signal(SignalKind::hangup()) else { return };
    while hangup.recv().await.is_some() {
        reload(&gateway, allow.as_ref());
    }
}

fn allowed(path: Option<&PathBuf>) -> Result<Option<HashSet<PublicKey>>, String> {
    let Some(path) = path else { return Ok(None) };
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    allowlist(&text).map(Some).map_err(|e| format!("{}: {e}", path.display()))
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let dir = cli.home.unwrap_or_else(Home::default_dir);
    let resolver = Resolver::new(Home::new(dir.clone()), Local::new(dir));
    let origin = cli.origin.unwrap_or_else(|| format!("http://{}", cli.bind));
    let allow = match allowed(cli.allow.as_ref()) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: allow {e}");
            return ExitCode::FAILURE;
        }
    };
    let gateway = match Gateway::new(resolver, origin.clone(), allow) {
        Ok(g) => Arc::new(g.pull_cap(cli.pulls).budget(cli.budget.saturating_mul(MIB))),
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let listener = match TcpListener::bind(cli.bind).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: bind {}: {e}", cli.bind);
            return ExitCode::FAILURE;
        }
    };
    println!("listening on http://{}", cli.bind);
    println!("login at {origin}/login");
    println!("pulls {} in flight, budget {} MiB per identity per hour", cli.pulls, cli.budget);
    tokio::spawn(on_hangup(Arc::clone(&gateway), cli.allow));
    match weft_gateway::serve(listener, gateway).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
