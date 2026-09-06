#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use weft_core::{Body, SecretKey};
use weft_home::{Home, home, keystore};
use weft_store::{Client, Result, socket_path};

const PASS_ENV: &str = "WEFT_APP_PASSPHRASE";

#[derive(Parser, Debug)]
#[command(name = "weft-app", version, about = "A sample application that holds a grant")]
struct Cli {
    #[arg(long, global = true, env = "WEFT_HOME")]
    home: Option<PathBuf>,
    #[arg(long, global = true, env = "WEFT_APP_KEY")]
    key: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Key,
    Whoami,
    Read { kind: String },
    Write { kind: String, file: PathBuf },
}

fn default_key() -> PathBuf {
    Home::default_dir().with_file_name("weft-app").join("app.key")
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let socket = socket_path(&cli.home.unwrap_or_else(Home::default_dir));
    let key = cli.key.unwrap_or_else(default_key);
    match run(&socket, &key, cli.command).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn open(key: &Path) -> Result<SecretKey> {
    Ok(keystore::open(key, &home::passphrase_from(PASS_ENV, false)?)?)
}

async fn run(socket: &Path, key: &Path, command: Command) -> Result<()> {
    match command {
        Command::Key => {
            let pass = home::passphrase_from(PASS_ENV, true)?;
            let meta = keystore::generate(key, &pass, "app", home::now()?, None)?;
            println!("{}", meta.public.address());
            println!("key {}", key.display());
        }
        Command::Whoami => println!("{}", keystore::meta(key)?.public.address()),
        Command::Read { kind } => {
            let mut client = Client::connect(socket, &open(key)?).await?;
            for address in client.list(&kind).await? {
                let record = client.get(address).await?;
                let Body::Inline(body) = record.body() else { continue };
                println!("{address}  created {}", record.created());
                println!("{}", String::from_utf8_lossy(body));
            }
        }
        Command::Write { kind, file } => {
            let body = std::fs::read(&file)?;
            let mut client = Client::connect(socket, &open(key)?).await?;
            println!("{}", client.put(&kind, body, vec![]).await?);
        }
    }
    Ok(())
}
