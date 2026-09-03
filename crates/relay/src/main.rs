#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use iroh::endpoint::presets;
use iroh::{Endpoint, SecretKey};
use weft_core::{Address, PublicKey};
use weft_net::Relay;

#[derive(Parser, Debug)]
#[command(name = "weft-relay", version, about = "A cache with a contract")]
struct Cli {
    #[arg(long, global = true, env = "WEFT_RELAY_DIR")]
    dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Init,
    Allow { address: Address },
    Deny { address: Address },
    Serve,
}

type Result<T> = core::result::Result<T, String>;

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let dir = cli.dir.unwrap_or_else(default_dir);
    match run(&dir, cli.command).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn default_dir() -> PathBuf {
    std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
        .unwrap_or_else(|| PathBuf::from("."))
        .join("weft-relay")
}

async fn run(dir: &Path, command: Command) -> Result<()> {
    match command {
        Command::Init => {
            if dir.join("relay.key").exists() {
                return Err(format!("relay already initialised at {}", dir.display()));
            }
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)
                .map_err(|e| e.to_string())?;
            let key = SecretKey::generate();
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(dir.join("relay.key"))
                .map_err(|e| e.to_string())?;
            f.write_all(&key.to_bytes()).map_err(|e| e.to_string())?;
            std::fs::write(dir.join("allow"), b"").map_err(|e| e.to_string())?;
            println!("{}", key.public());
            println!("dir {}", dir.display());
            Ok(())
        }
        Command::Allow { address } => {
            let mut set = allowlist(dir)?;
            set.insert(PublicKey::from_bytes(address.bytes()).map_err(|e| e.to_string())?);
            write_allowlist(dir, &set)
        }
        Command::Deny { address } => {
            let mut set = allowlist(dir)?;
            set.remove(&PublicKey::from_bytes(address.bytes()).map_err(|e| e.to_string())?);
            write_allowlist(dir, &set)
        }
        Command::Serve => serve(dir).await,
    }
}

fn secret(dir: &Path) -> Result<SecretKey> {
    let bytes = std::fs::read(dir.join("relay.key"))
        .map_err(|_| format!("no relay at {}; run init", dir.display()))?;
    let bytes: [u8; 32] = bytes.as_slice().try_into().map_err(|_| "relay.key is not 32 bytes")?;
    Ok(SecretKey::from_bytes(&bytes))
}

fn allowlist(dir: &Path) -> Result<HashSet<PublicKey>> {
    let text = std::fs::read_to_string(dir.join("allow"))
        .map_err(|_| format!("no relay at {}; run init", dir.display()))?;
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|l| {
            let a: Address = l.parse().map_err(|e: weft_core::Error| e.to_string())?;
            PublicKey::from_bytes(a.bytes()).map_err(|e| e.to_string())
        })
        .collect()
}

fn write_allowlist(dir: &Path, set: &HashSet<PublicKey>) -> Result<()> {
    let mut keys: Vec<_> = set.iter().collect();
    keys.sort();
    let text = keys.iter().fold(String::new(), |mut t, k| {
        use std::fmt::Write;
        let _ = writeln!(t, "{}", k.address());
        t
    });
    std::fs::write(dir.join("allow"), text).map_err(|e| e.to_string())?;
    println!("{} allowed", keys.len());
    Ok(())
}

async fn serve(dir: &Path) -> Result<()> {
    let key = secret(dir)?;
    let allow = allowlist(dir)?;
    let endpoint =
        Endpoint::builder(presets::N0).secret_key(key).bind().await.map_err(|e| e.to_string())?;
    let relay = Relay::open(endpoint, &dir.join("data"), allow).await.map_err(|e| e.to_string())?;
    println!("{}", relay.id());
    let router = relay.spawn();
    router.endpoint().online().await;
    println!("online");
    tokio::signal::ctrl_c().await.map_err(|e| e.to_string())?;
    router.shutdown().await.map_err(|e| e.to_string())?;
    Ok(())
}
