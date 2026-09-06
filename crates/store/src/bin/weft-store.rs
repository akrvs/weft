#![forbid(unsafe_code)]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tokio::net::{UnixListener, UnixStream};
use weft_home::{Home, Store, home};
use weft_store::{Error, Gate, Result, socket_path};

#[derive(Parser, Debug)]
#[command(name = "weft-store", version, about = "The personal store as a gate")]
struct Cli {
    #[arg(long, global = true, env = "WEFT_HOME")]
    home: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Serve {
        #[arg(long)]
        device: String,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let home = Home::new(cli.home.unwrap_or_else(Home::default_dir));
    let Command::Serve { device } = cli.command;
    match serve(home, &device).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn bind(path: &std::path::Path) -> Result<UnixListener> {
    if path.exists() {
        if UnixStream::connect(path).await.is_ok() {
            return Err(Error::Io(format!("a store is already serving {}", path.display())));
        }
        std::fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

async fn serve(home: Home, device: &str) -> Result<()> {
    let root = home.root()?;
    let key = home.open(device, &home::passphrase(false)?)?;
    let records = home.store().all()?;
    let manifest = Store::manifest(&records, &root);
    let authorized = key.public() == root
        || manifest
            .as_ref()
            .is_some_and(|m| m.authorizes(&key.public(), home::now().unwrap_or(0)).is_ok());
    if !authorized {
        eprintln!("warning: {device} is not in the current manifest; writes will be refused");
    }
    let path = socket_path(home.path());
    let listener = bind(&path).await?;
    println!("{}", path.display());
    println!("root    {}", root.address());
    println!("signer  {}  {device}", key.public().address());
    let gate = Arc::new(Gate::new(home, root, key));
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        r = weft_store::serve(gate, listener) => r?,
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
    let _ = std::fs::remove_file(&path);
    Ok(())
}
