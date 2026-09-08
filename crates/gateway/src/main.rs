#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use tokio::net::TcpListener;
use weft_core::PublicKey;
use weft_gateway::login::allowlist;
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
    let gateway = match weft_gateway::Gateway::new(resolver, origin.clone(), allow) {
        Ok(g) => Arc::new(g),
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
    match weft_gateway::serve(listener, gateway).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
