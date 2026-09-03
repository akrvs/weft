#![forbid(unsafe_code)]

mod fail;
mod fs;
mod home;
mod keystore;
mod store;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use weft_core::{Address, Body, Draft, Manifest, Pointer, Record, verify};

use crate::fail::{Result, fail};
use crate::home::{Home, ROOT};
use crate::store::Store;

#[derive(Parser, Debug)]
#[command(name = "weft", version, about = "Signed, content-addressed records you hold the keys to")]
struct Cli {
    #[arg(long, global = true, env = "WEFT_HOME")]
    home: Option<PathBuf>,
    #[arg(long, global = true)]
    dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Init,
    Whoami,
    Device {
        #[command(subcommand)]
        command: DeviceCommand,
    },
    Manifest,
    Sign {
        file: PathBuf,
        #[arg(long, default_value = "page")]
        kind: String,
        #[arg(long = "as", default_value = ROOT)]
        signer: String,
        #[arg(long = "ref")]
        refs: Vec<Address>,
    },
    Point {
        name: String,
        target: Address,
        #[arg(long = "as", default_value = ROOT)]
        signer: String,
    },
    Verify {
        file: PathBuf,
        #[arg(long)]
        manifest: Option<PathBuf>,
    },
    Inspect {
        file: PathBuf,
    },
    Resolve {
        author: Address,
        name: String,
    },
}

#[derive(Subcommand, Debug)]
enum DeviceCommand {
    Add {
        label: String,
        #[arg(long)]
        expires: Option<u64>,
    },
    Revoke {
        label: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let home = Home::new(cli.home.unwrap_or_else(Home::default_dir));
    let store = cli.dir.map_or_else(|| home.store(), Store::new);
    match run(&home, &store, cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(home: &Home, store: &Store, command: Command) -> Result<()> {
    match command {
        Command::Init => init(home),
        Command::Whoami => whoami(home),
        Command::Device { command: DeviceCommand::Add { label, expires } } => {
            let meta = home.add_device(&label, &home::passphrase(false)?, expires)?;
            println!("{}  {}", meta.public.address(), meta.label);
            println!("publish a new manifest with `weft manifest`");
            Ok(())
        }
        Command::Device { command: DeviceCommand::Revoke { label } } => {
            let key = home.revoke(&label)?;
            println!("revoked {}  {label}", key.address());
            println!("publish a new manifest with `weft manifest`");
            Ok(())
        }
        Command::Manifest => manifest(home, store),
        Command::Sign { file, kind, signer, refs } => sign(home, store, &file, kind, &signer, refs),
        Command::Point { name, target, signer } => point(home, store, name, target, &signer),
        Command::Verify { file, manifest } => verify_file(store, &file, manifest.as_deref()),
        Command::Inspect { file } => inspect(&store::read_record(&file)?),
        Command::Resolve { author, name } => resolve(store, author, &name),
    }
}

fn init(home: &Home) -> Result<()> {
    let meta = home.init(&home::passphrase(true)?)?;
    println!("{}", meta.public.address());
    println!("home {}", home.path().display());
    Ok(())
}

fn whoami(home: &Home) -> Result<()> {
    println!("{}  root", home.root()?.address());
    for d in home.devices()? {
        let expiry = d.expires.map_or(String::new(), |e| format!("  expires {e}"));
        println!("{}  {}  created {}{expiry}", d.public.address(), d.label, d.created);
    }
    for r in home.revoked()? {
        println!("{}  revoked", r.address());
    }
    Ok(())
}

fn manifest(home: &Home, store: &Store) -> Result<()> {
    let root = home.root()?;
    let records = store.all()?;
    let prev = records
        .iter()
        .filter(|r| r.author() == &root && r.kind() == weft_core::manifest::KIND)
        .filter_map(|r| Manifest::from_record(r).ok().map(|m| (r.address(), m)))
        .max_by_key(|(_, m)| m.seq);
    let next = home.manifest(prev.as_ref().map(|(_, m)| m), prev.as_ref().map(|(a, _)| *a))?;
    let key = home.open(ROOT, &home::passphrase(false)?)?;
    let created = home::now()?;
    let record = next.draft(&root, created).sign(&key)?;
    let path = store.put(&record)?;
    let heads = Store::pointers(&records, &root, weft_core::pointer::MANIFEST, None);
    let seq = heads.iter().map(|(_, p)| p.seq).max().map_or(1, |s| s.saturating_add(1));
    let prev_heads = Store::head(&heads).map(|(r, _)| r.address()).into_iter().collect();
    let pointer = Pointer {
        name: weft_core::pointer::MANIFEST.to_owned(),
        target: record.address(),
        seq,
        prev: prev_heads,
    };
    let pointer_record = pointer.draft(&root, &root, created).sign(&key)?;
    let pointer_path = store.put(&pointer_record)?;
    println!("manifest seq {}  {}", next.seq, path.display());
    println!("pointer  seq {seq}  {}", pointer_path.display());
    Ok(())
}

fn sign(
    home: &Home,
    store: &Store,
    file: &std::path::Path,
    kind: String,
    signer: &str,
    refs: Vec<Address>,
) -> Result<()> {
    let data = std::fs::read(file)?;
    let body = if data.len() > weft_core::record::MAX_INLINE {
        return fail(format!(
            "file exceeds inline limit of {} bytes",
            weft_core::record::MAX_INLINE
        ));
    } else {
        Body::Inline(data)
    };
    let key = home.open(signer, &home::passphrase(false)?)?;
    let draft = Draft {
        author: home.root()?,
        signer: key.public(),
        kind,
        created: home::now()?,
        refs,
        body,
    };
    let record = draft.sign(&key)?;
    println!("{}", store.put(&record)?.display());
    Ok(())
}

fn point(home: &Home, store: &Store, name: String, target: Address, signer: &str) -> Result<()> {
    let root = home.root()?;
    let records = store.all()?;
    let manifest = Store::manifest(&records, &root);
    let existing = Store::pointers(&records, &root, &name, manifest.as_ref());
    let seq = existing.iter().map(|(_, p)| p.seq).max().map_or(1, |s| s.saturating_add(1));
    let prev = Store::head(&existing).map(|(r, _)| r.address()).into_iter().collect();
    let key = home.open(signer, &home::passphrase(false)?)?;
    let pointer = Pointer { name, target, seq, prev };
    let record = pointer.draft(&root, &key.public(), home::now()?).sign(&key)?;
    verify(&record, manifest.as_ref())?;
    println!("{}", store.put(&record)?.display());
    Ok(())
}

fn verify_file(
    store: &Store,
    file: &std::path::Path,
    manifest_path: Option<&std::path::Path>,
) -> Result<()> {
    let record = store::read_record(file)?;
    let manifest = match manifest_path {
        Some(p) => Some(Manifest::from_record(&store::read_record(p)?)?),
        None if record.self_signed() => None,
        None => Store::manifest(&store.all()?, record.author()),
    };
    let v = verify(&record, manifest.as_ref())?;
    println!("ok      {}", v.address);
    println!("kind    {}", v.kind);
    println!("author  {}", v.author);
    println!("signer  {}", v.signer);
    Ok(())
}

fn inspect(record: &Record) -> Result<()> {
    println!("address {}", record.address());
    println!("kind    {}", record.kind());
    println!("author  {}", record.author().address());
    println!("signer  {}", record.signer().address());
    println!("created {}", record.created());
    for r in record.refs() {
        println!("ref     {r}");
    }
    match record.body() {
        Body::Inline(b) => println!("body    {} bytes inline", b.len()),
        Body::Blob(a) => println!("blob    {a}"),
    }
    match record.kind() {
        weft_core::manifest::KIND => {
            let m = Manifest::from_record(record)?;
            println!("seq     {}", m.seq);
            for d in &m.devices {
                println!("device  {}  {}", d.key.address(), d.label);
            }
            for k in &m.revoked {
                println!("revoked {}", k.address());
            }
        }
        weft_core::pointer::KIND => {
            let p = Pointer::from_record(record)?;
            println!("name    {}", p.name);
            println!("seq     {}", p.seq);
            println!("target  {}", p.target);
        }
        _ => {}
    }
    println!("sig     {}", record.check_signature().map_or("invalid", |()| "valid"));
    Ok(())
}

fn resolve(store: &Store, author: Address, name: &str) -> Result<()> {
    let author = weft_core::PublicKey::from_bytes(author.bytes())?;
    let records = store.all()?;
    let manifest = Store::manifest(&records, &author);
    let pointers = Store::pointers(&records, &author, name, manifest.as_ref());
    let Some((record, pointer)) = Store::head(&pointers) else {
        return fail(format!("no valid pointer named {name} by {}", author.address()));
    };
    let present = records.iter().any(|r| r.address() == pointer.target);
    println!("{}", pointer.target);
    println!(
        "seq {}  signer {}  pointer {}",
        pointer.seq,
        record.signer().address(),
        record.address()
    );
    println!("target {}", if present { "present" } else { "absent" });
    Ok(())
}
