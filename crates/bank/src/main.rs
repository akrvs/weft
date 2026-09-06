#![forbid(unsafe_code)]

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use weft_core::{PublicKey, SecretKey, Voucher};

#[derive(Parser, Debug)]
#[command(name = "weft-bank", version, about = "Mints vouchers a relay takes as payment")]
struct Cli {
    #[arg(long, global = true, env = "WEFT_BANK_DIR")]
    dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Init,
    Whoami,
    Mint {
        #[arg(long)]
        to: iroh::EndpointId,
        #[arg(long)]
        cents: u64,
        #[arg(long)]
        out: PathBuf,
    },
}

type Result<T> = core::result::Result<T, String>;

fn main() -> ExitCode {
    let cli = Cli::parse();
    let dir = cli.dir.unwrap_or_else(default_dir);
    match run(&dir, cli.command) {
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
        .join("weft-bank")
}

fn run(dir: &Path, command: Command) -> Result<()> {
    match command {
        Command::Init => {
            if dir.join("bank.key").exists() {
                return Err(format!("bank already initialised at {}", dir.display()));
            }
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)
                .map_err(|e| e.to_string())?;
            let seed = random()?;
            write_private(&dir.join("bank.key"), &seed)?;
            println!("{}", SecretKey::from_seed(seed).public().address());
            println!("dir {}", dir.display());
            Ok(())
        }
        Command::Whoami => {
            println!("{}", secret(dir)?.public().address());
            Ok(())
        }
        Command::Mint { to, cents, out } => {
            let bank = secret(dir)?;
            let to = PublicKey::from_bytes(to.as_bytes()).map_err(|e| e.to_string())?;
            let voucher = Voucher::mint(&bank, to, cents, random()?).map_err(|e| e.to_string())?;
            write_private(&out, &voucher.encode())?;
            println!("{}", voucher.id());
            println!("{cents} cents to {}", to.address());
            Ok(())
        }
    }
}

fn random() -> Result<[u8; 32]> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| e.to_string())?;
    Ok(bytes)
}

fn secret(dir: &Path) -> Result<SecretKey> {
    let bytes = std::fs::read(dir.join("bank.key"))
        .map_err(|_| format!("no bank at {}; run init", dir.display()))?;
    let seed: [u8; 32] = bytes.as_slice().try_into().map_err(|_| "bank.key is not 32 bytes")?;
    Ok(SecretKey::from_seed(seed))
}

fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    f.write_all(data).map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())
}
