#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use iroh::SecretKey;
use tokio::signal::unix::{SignalKind, signal};
use weft_core::{Address, PublicKey};
use weft_net::{Fake, Net, Node, Pricing, Relay};
use weft_relay::lnd;

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
    Allow {
        address: Address,
    },
    Deny {
        address: Address,
    },
    Rate {
        cents: u64,
    },
    Sats {
        sats: u64,
    },
    Node {
        #[command(subcommand)]
        command: NodeCommand,
    },
    Bank {
        #[command(subcommand)]
        command: BankCommand,
    },
    Price,
    Serve,
}

#[derive(Subcommand, Debug)]
enum BankCommand {
    Add { address: Address },
    Remove { address: Address },
}

#[derive(Subcommand, Debug)]
enum NodeCommand {
    Fake,
    Lnd { url: String },
    None,
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
            let mut set = keys(dir, "allow")?;
            set.insert(key_of(&address)?);
            write_keys(dir, "allow", &set)
        }
        Command::Deny { address } => {
            let mut set = keys(dir, "allow")?;
            set.remove(&key_of(&address)?);
            write_keys(dir, "allow", &set)
        }
        Command::Rate { cents } => {
            keys(dir, "allow")?;
            std::fs::write(dir.join("rate"), format!("{cents}\n")).map_err(|e| e.to_string())?;
            println!("{cents} cents per KiB per day");
            Ok(())
        }
        Command::Sats { sats } => {
            keys(dir, "allow")?;
            std::fs::write(dir.join("sats"), format!("{sats}\n")).map_err(|e| e.to_string())?;
            println!("{sats} sats per cent");
            Ok(())
        }
        Command::Node { command } => {
            keys(dir, "allow")?;
            let path = dir.join("node");
            match command {
                NodeCommand::Fake => std::fs::write(&path, "fake\n").map_err(|e| e.to_string())?,
                NodeCommand::Lnd { url } => {
                    lnd::Lnd::open(&url, dir)?;
                    std::fs::write(&path, format!("lnd {url}\n")).map_err(|e| e.to_string())?;
                }
                NodeCommand::None => {
                    if let Err(e) = std::fs::remove_file(&path)
                        && e.kind() != std::io::ErrorKind::NotFound
                    {
                        return Err(e.to_string());
                    }
                }
            }
            match node(dir)? {
                Some(n) => println!("node {n}"),
                None => println!("no node"),
            }
            Ok(())
        }
        Command::Bank { command: BankCommand::Add { address } } => {
            let mut set = keys(dir, "banks")?;
            set.insert(key_of(&address)?);
            write_keys(dir, "banks", &set)
        }
        Command::Bank { command: BankCommand::Remove { address } } => {
            let mut set = keys(dir, "banks")?;
            set.remove(&key_of(&address)?);
            write_keys(dir, "banks", &set)
        }
        Command::Price => {
            let pricing = pricing(dir)?;
            println!("rate {} cents per KiB per day", pricing.rate);
            let mut banks: Vec<_> = pricing.banks.iter().collect();
            banks.sort();
            for bank in banks {
                println!("bank {}", bank.address());
            }
            println!("sats {} per cent", pricing.sats);
            match node(dir)? {
                Some(n) => println!("node {n}"),
                None => println!("no node"),
            }
            Ok(())
        }
        Command::Serve => serve(dir).await,
    }
}

fn key_of(address: &Address) -> Result<PublicKey> {
    PublicKey::from_bytes(address.bytes()).map_err(|e| e.to_string())
}

fn secret(dir: &Path) -> Result<SecretKey> {
    let bytes = std::fs::read(dir.join("relay.key"))
        .map_err(|_| format!("no relay at {}; run init", dir.display()))?;
    let bytes: [u8; 32] = bytes.as_slice().try_into().map_err(|_| "relay.key is not 32 bytes")?;
    Ok(SecretKey::from_bytes(&bytes))
}

fn keys(dir: &Path, name: &str) -> Result<HashSet<PublicKey>> {
    if !dir.join("relay.key").is_file() {
        return Err(format!("no relay at {}; run init", dir.display()));
    }
    let text = std::fs::read_to_string(dir.join(name)).unwrap_or_default();
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|l| {
            let a: Address = l.parse().map_err(|e: weft_core::Error| e.to_string())?;
            key_of(&a)
        })
        .collect()
}

fn write_keys(dir: &Path, name: &str, set: &HashSet<PublicKey>) -> Result<()> {
    let mut keys: Vec<_> = set.iter().collect();
    keys.sort();
    let text = keys.iter().fold(String::new(), |mut t, k| {
        use std::fmt::Write;
        let _ = writeln!(t, "{}", k.address());
        t
    });
    std::fs::write(dir.join(name), text).map_err(|e| e.to_string())?;
    println!("{} in {name}", keys.len());
    Ok(())
}

fn number(dir: &Path, name: &str) -> Result<u64> {
    match std::fs::read_to_string(dir.join(name)) {
        Ok(text) => text.trim().parse::<u64>().map_err(|e| format!("{name}: {e}")),
        Err(_) => Ok(0),
    }
}

fn pricing(dir: &Path) -> Result<Pricing> {
    let banks = keys(dir, "banks")?;
    Ok(Pricing { rate: number(dir, "rate")?, banks, sats: number(dir, "sats")? })
}

fn node(dir: &Path) -> Result<Option<String>> {
    match std::fs::read_to_string(dir.join("node")) {
        Ok(text) => Ok(Some(text.trim().to_owned())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("node: {e}")),
    }
}

fn open_node(dir: &Path) -> Result<Option<std::sync::Arc<dyn Node>>> {
    let Some(line) = node(dir)? else { return Ok(None) };
    let node: std::sync::Arc<dyn Node> = match line.split_once(' ') {
        None if line == "fake" => {
            std::sync::Arc::new(Fake::new(&dir.join("data")).map_err(|e| e.to_string())?)
        }
        Some(("lnd", url)) => std::sync::Arc::new(lnd::Lnd::open(url.trim(), dir)?),
        _ => return Err(format!("node: unknown line {line:?}")),
    };
    Ok(Some(node))
}

fn reload(dir: &Path, relay: &Relay) {
    match keys(dir, "allow").and_then(|allow| pricing(dir).map(|pricing| (allow, pricing))) {
        Ok((allow, pricing)) => {
            eprintln!(
                "reload: {} allowed authors, rate {}, sats {}",
                allow.len(),
                pricing.rate,
                pricing.sats
            );
            relay.reload(allow, pricing);
        }
        Err(e) => eprintln!("reload: {e}, keeping the old config"),
    }
    match relay.sweep(weft_net::relay::now()) {
        Ok(swept) => eprintln!("reload: swept {} records", swept.records.len()),
        Err(e) => eprintln!("reload: sweep {e}"),
    }
}

async fn serve(dir: &Path) -> Result<()> {
    let key = secret(dir)?;
    let allow = keys(dir, "allow")?;
    let pricing = pricing(dir)?;
    let net = Net::from_env().map_err(|e| e.to_string())?;
    let endpoint = net.bind(Some(key)).await.map_err(|e| e.to_string())?;
    let every = Duration::from_secs(60);
    let node = open_node(dir)?;
    let mut relay = Relay::open(endpoint, &dir.join("data"), allow, pricing, every)
        .await
        .map_err(|e| e.to_string())?;
    if let Some(node) = node {
        relay = relay.with_node(node);
    }
    println!("{}", relay.id());
    let sweeper = relay.sweeper(every);
    let router = relay.clone().spawn();
    net.online(router.endpoint()).await;
    let addrs: Vec<String> = router.endpoint().addr().ip_addrs().map(ToString::to_string).collect();
    if !addrs.is_empty() {
        println!("entry    {}@{}", relay.id(), addrs.join(","));
    }
    println!("online");
    let mut hangup = signal(SignalKind::hangup()).map_err(|e| e.to_string())?;
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            Some(()) = hangup.recv() => reload(dir, &relay),
        }
    }
    sweeper.abort();
    router.shutdown().await.map_err(|e| e.to_string())?;
    Ok(())
}
