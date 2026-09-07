#![forbid(unsafe_code)]

use std::io::{BufRead, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tokio::net::{UnixListener, UnixStream};
use weft_home::{Home, home};
use weft_store::{
    Error, Gate, Result, browser_key, browser_key_path, create_browser_key, socket_path,
};
use zeroize::Zeroizing;

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
        #[arg(long)]
        attach: bool,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let home = Home::new(cli.home.unwrap_or_else(Home::default_dir));
    let Command::Serve { device, attach } = cli.command;
    match serve(home, &device, attach).await {
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

fn passphrase_line() -> Result<Zeroizing<Vec<u8>>> {
    let mut line = Zeroizing::new(String::new());
    std::io::stdin().lock().read_line(&mut line)?;
    let trimmed = line.trim_end_matches(['\r', '\n']);
    if trimmed.is_empty() {
        return Err(Error::Home("passphrase must not be empty".to_owned()));
    }
    Ok(Zeroizing::new(trimmed.as_bytes().to_vec()))
}

async fn stdin_closed() {
    let _ = tokio::task::spawn_blocking(|| {
        let mut sink = [0u8; 64];
        let mut stdin = std::io::stdin().lock();
        while matches!(stdin.read(&mut sink), Ok(n) if n > 0) {}
    })
    .await;
}

async fn serve(home: Home, device: &str, attach: bool) -> Result<()> {
    let root = home.root()?;
    let pass = if attach { passphrase_line()? } else { home::passphrase(false)? };
    let key = home.open(device, &pass)?;
    drop(pass);
    let snap = home.store().snapshot()?;
    let manifest = snap.manifest(&root);
    let authorized = key.public() == root
        || manifest
            .as_ref()
            .is_some_and(|m| m.authorizes(&key.public(), home::now().unwrap_or(0)).is_ok());
    if !authorized {
        eprintln!("warning: {device} is not in the current manifest; writes will be refused");
    }
    let browser = if browser_key_path(home.path()).exists() {
        browser_key(home.path())?
    } else {
        create_browser_key(home.path())?
    }
    .public();
    let path = socket_path(home.path());
    let listener = bind(&path).await?;
    println!("{}", path.display());
    println!("root     {}", root.address());
    println!("signer   {}  {device}", key.public().address());
    println!("browser  {}", browser.address());
    let gate = Arc::new(Gate::new(home, root, key, browser));
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        r = weft_store::serve(gate, listener) => r?,
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
        () = stdin_closed(), if attach => {}
    }
    let _ = std::fs::remove_file(&path);
    Ok(())
}
