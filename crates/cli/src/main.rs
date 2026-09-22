#![forbid(unsafe_code)]

#[macro_use]
mod say;
mod lists;
mod net;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use data_encoding::HEXLOWER;
use weft_core::recovery::{Message, Signature};
use weft_core::{
    Access, Address, Body, Challenge, Draft, Grant, Guardians, Manifest, Payment, Pointer, Proof,
    PublicKey, Receipt, Record, Recovery, Revoke, Voucher, verify,
};

use weft_home::{Home, ROOT, Relay, Result, Snapshot, Store, fail, home, read_record};
use weft_resolve::Resolver;

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
    Manifest {
        #[arg(long = "guardian")]
        guardians: Vec<Address>,
        #[arg(long)]
        threshold: Option<usize>,
    },
    Recover {
        #[command(subcommand)]
        command: RecoverCommand,
    },
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
        #[arg(long)]
        relay: bool,
    },
    Dns {
        domain: String,
    },
    Relay {
        #[command(subcommand)]
        command: RelayCommand,
    },
    Push {
        addresses: Vec<Address>,
        #[arg(long, conflicts_with = "preimage")]
        pay: Option<PathBuf>,
        #[arg(long)]
        preimage: Option<String>,
        #[arg(long)]
        relay: Option<String>,
        #[arg(long, default_value = "30")]
        days: u64,
        #[arg(long = "as", default_value = ROOT)]
        signer: String,
    },
    Invoice {
        addresses: Vec<Address>,
        #[arg(long, default_value = "30")]
        days: u64,
        #[arg(long)]
        relay: Option<String>,
    },
    Price,
    Receipts,
    Fetch {
        address: Address,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    Grant {
        #[command(subcommand)]
        command: GrantCommand,
    },
    Login {
        #[command(subcommand)]
        command: LoginCommand,
    },
    Petname {
        #[command(subcommand)]
        command: lists::PetnameCommand,
    },
    Label {
        #[command(subcommand)]
        command: lists::LabelCommand,
    },
}

#[derive(Subcommand, Debug)]
enum LoginCommand {
    Challenge {
        #[arg(long)]
        service: String,
        #[arg(long, default_value_t = 300)]
        ttl: u64,
    },
    Sign {
        challenge: String,
        #[arg(long = "as", default_value = ROOT)]
        signer: String,
    },
    Verify {
        proof: String,
        #[arg(long)]
        service: String,
    },
}

#[derive(Subcommand, Debug)]
enum RecoverCommand {
    Draft {
        root: Address,
    },
    Sign {
        message: String,
    },
    Finish {
        message: String,
        #[arg(long = "sig", required = true)]
        sigs: Vec<String>,
    },
}

#[derive(Subcommand, Debug)]
enum RelayCommand {
    Add { relay: Relay },
    List,
}

#[derive(Subcommand, Debug)]
enum GrantCommand {
    Add {
        app: Address,
        #[arg(long = "kind", required = true)]
        kinds: Vec<String>,
        #[arg(long)]
        read: bool,
        #[arg(long)]
        write: bool,
        #[arg(long)]
        expires: Option<u64>,
        #[arg(long = "as", default_value = ROOT)]
        signer: String,
    },
    List,
    Revoke {
        grant: Address,
        #[arg(long = "as", default_value = ROOT)]
        signer: String,
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
    Retire {
        label: String,
        #[arg(long)]
        at: Option<u64>,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let home = Home::new(cli.home.unwrap_or_else(Home::default_dir));
    let store = cli.dir.map_or_else(|| home.store(), Store::new);
    match run(&home, &store, cli.command).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(home: &Home, store: &Store, command: Command) -> Result<()> {
    match command {
        Command::Init => init(home),
        Command::Whoami => whoami(home),
        Command::Device { command: DeviceCommand::Add { label, expires } } => {
            let meta = home.add_device(&label, &home::passphrase(false)?, expires)?;
            say!("{}  {}", meta.public.address(), meta.label);
            say!("publish a new manifest with `weft manifest`");
            Ok(())
        }
        Command::Device { command: DeviceCommand::Revoke { label } } => {
            let key = home.revoke(&label)?;
            say!("revoked {}  {label}", key.address());
            say!("publish a new manifest with `weft manifest`");
            Ok(())
        }
        Command::Device { command: DeviceCommand::Retire { label, at } } => {
            let (key, at) = home.retire(&label, &home::passphrase(false)?, at)?;
            say!("retired {}  {label}  expires {at}", key.address());
            say!("publish a new manifest with `weft manifest`");
            Ok(())
        }
        Command::Manifest { guardians, threshold } => manifest(home, store, &guardians, threshold),
        Command::Recover { command } => recover(home, store, command),
        Command::Sign { file, kind, signer, refs } => sign(home, store, &file, kind, &signer, refs),
        Command::Point { name, target, signer } => point(home, store, &name, target, &signer),
        Command::Verify { file, manifest } => verify_file(store, &file, manifest.as_deref()),
        Command::Inspect { file } => inspect(&read_record(&file)?),
        Command::Resolve { author, name, relay: false } => {
            resolve(home, store, author, &name).await
        }
        Command::Resolve { author, name, relay: true } => {
            net::resolve(home, store, author, &name).await
        }
        Command::Dns { domain } => dns(&domain).await,
        Command::Relay { command: RelayCommand::Add { relay } } => home.add_relay(relay),
        Command::Relay { command: RelayCommand::List } => {
            for id in home.relays()? {
                say!("{id}");
            }
            Ok(())
        }
        Command::Push { addresses, pay: None, preimage: None, .. } => {
            net::push(home, store, &addresses, None).await.map(drop)
        }
        Command::Push { addresses, pay: voucher, preimage, relay, days, signer } => {
            let (relay, payment) = match (voucher, preimage) {
                (Some(path), None) => {
                    let voucher = Voucher::decode(&std::fs::read(path)?)?;
                    let relay = net::pick_relay(home, None, Some(&voucher.to))?;
                    (relay, Payment::Voucher(Box::new(voucher)))
                }
                (None, Some(hex)) => {
                    let relay = net::pick_relay(home, relay.as_deref(), None)?;
                    let preimage =
                        weft_net::node::decode_preimage(&hex).map_err(|e| e.to_string())?;
                    (relay, Payment::Preimage(preimage))
                }
                _ => return fail("pay with --pay <voucher> or --preimage <hex>, not both"),
            };
            push_paid(home, store, &addresses, relay, payment, days, &signer).await
        }
        Command::Invoice { addresses, days, relay } => {
            net::invoice(home, store, &addresses, days, relay.as_deref()).await
        }
        Command::Price => net::price(home).await,
        Command::Receipts => receipts(home, store),
        Command::Fetch { address, out } => net::fetch(home, store, address, out.as_deref()).await,
        Command::Grant {
            command: GrantCommand::Add { app, kinds, read, write, expires, signer },
        } => grant_add(home, store, app, kinds, (read, write), expires, &signer),
        Command::Grant { command: GrantCommand::List } => grant_list(home, store).await,
        Command::Grant { command: GrantCommand::Revoke { grant, signer } } => {
            grant_revoke(home, store, grant, &signer)
        }
        Command::Login { command: LoginCommand::Challenge { service, ttl } } => {
            let mut nonce = [0u8; 32];
            getrandom::fill(&mut nonce).map_err(|e| e.to_string())?;
            let expires = home::now()?.saturating_add(ttl);
            let challenge = Challenge { service, nonce, expires };
            challenge.check()?;
            say!("{}", challenge.to_text());
            Ok(())
        }
        Command::Petname { command } => lists::petname(home, store, command).await,
        Command::Label { command } => lists::label(home, store, command).await,
        Command::Login { command: LoginCommand::Sign { challenge, signer } } => {
            login_sign(home, store, &challenge, &signer)
        }
        Command::Login { command: LoginCommand::Verify { proof, service } } => {
            let proof = Proof::from_text(&proof)?;
            let local = store.snapshot()?.manifest(proof.login.author());
            let login = proof.verify(&service, home::now()?, local.as_ref())?;
            say!("{}", login.author.address());
            say!("signer  {}", login.signer.address());
            say!("expires {}", login.challenge.expires);
            Ok(())
        }
    }
}

fn login_sign(home: &Home, store: &Store, challenge: &str, signer: &str) -> Result<()> {
    let challenge = Challenge::from_text(challenge)?;
    let root = home.root()?;
    let key = home.open(signer, &home::passphrase(false)?)?;
    let record = challenge.draft(&root, &key.public(), home::now()?).sign(&key)?;
    let snap = store.snapshot()?;
    let manifest = snap.manifest_record(&root).map(|r| (*r).clone());
    verify(&record, manifest.as_ref().and_then(|r| Manifest::from_record(r).ok()).as_ref())?;
    let proof = Proof { login: record, manifest };
    say!("{}", proof.to_text());
    Ok(())
}

fn draft_own(
    home: &Home,
    store: &Store,
    signer: &str,
    draft: impl FnOnce(&weft_core::PublicKey, &weft_core::PublicKey, u64) -> Draft,
) -> Result<Record> {
    let root = home.root()?;
    let key = home.open(signer, &home::passphrase(false)?)?;
    let record = draft(&root, &key.public(), home::now()?).sign(&key)?;
    let manifest = store.snapshot()?.manifest(&root);
    verify(&record, manifest.as_ref())?;
    Ok(record)
}

fn sign_own(
    home: &Home,
    store: &Store,
    signer: &str,
    draft: impl FnOnce(&weft_core::PublicKey, &weft_core::PublicKey, u64) -> Draft,
) -> Result<Record> {
    let record = draft_own(home, store, signer, draft)?;
    store.put(&record)?;
    Ok(record)
}

fn relay_id(key: &weft_core::PublicKey) -> Result<iroh::EndpointId> {
    iroh::EndpointId::from_bytes(key.bytes()).map_err(|e| e.to_string().into())
}

fn pay(
    home: &Home,
    store: &Store,
    addresses: &[Address],
    relay: Relay,
    payment: Payment,
    days: u64,
    signer: &str,
) -> Result<net::Paid> {
    if addresses.is_empty() {
        return fail("name the records the payment is for");
    }
    net::check_days(days)?;
    let mut records = addresses.to_vec();
    records.sort_unstable();
    records.dedup();
    let until = home::now()?.saturating_add(days.saturating_mul(86_400));
    let key = weft_core::PublicKey::from_bytes(relay.id.as_bytes())?;
    let receipt = Receipt { relay: key, records, until, payment };
    receipt.check()?;
    let record = draft_own(home, store, signer, |root, signer, created| {
        receipt.draft(root, signer, created)
    })?;
    say!("receipt {}  {} until {until}", record.address(), paid_with(&receipt.payment));
    Ok(net::Paid { relay, receipt: record })
}

async fn push_paid(
    home: &Home,
    store: &Store,
    addresses: &[Address],
    relay: Relay,
    payment: Payment,
    days: u64,
    signer: &str,
) -> Result<()> {
    let paid = pay(home, store, addresses, relay, payment, days, signer)?;
    let receipt = paid.receipt.clone();
    let stored = net::push(home, store, addresses, Some(paid)).await?;
    if !stored.contains(&receipt.address()) {
        return fail("receipt refused, nothing kept");
    }
    store.put(&receipt)?;
    Ok(())
}

fn paid_with(payment: &Payment) -> String {
    payment.cents().map_or_else(|| "lightning".to_owned(), |cents| format!("{cents} cents"))
}

fn receipts(home: &Home, store: &Store) -> Result<()> {
    let root = home.root()?;
    let snap = store.snapshot()?;
    let manifest = snap.manifest(&root);
    let mut receipts: Vec<(Arc<Record>, Receipt)> = snap
        .own(&root, manifest.as_ref())
        .filter(|r| r.kind() == weft_core::receipt::KIND)
        .filter_map(|r| Receipt::from_record(&r).ok().map(|x| (r, x)))
        .collect();
    receipts.sort_by_key(|(r, _)| r.created());
    for (record, receipt) in receipts {
        say!(
            "{}  {}  {}  {} records  until {}",
            record.address(),
            relay_id(&receipt.relay)?,
            paid_with(&receipt.payment),
            receipt.records.len(),
            receipt.until
        );
    }
    Ok(())
}

fn grant_add(
    home: &Home,
    store: &Store,
    app: Address,
    mut kinds: Vec<String>,
    (read, write): (bool, bool),
    expires: Option<u64>,
    signer: &str,
) -> Result<()> {
    let access = match (read, write) {
        (true, false) => Access::Read,
        (false, true) => Access::Write,
        (true, true) => Access::ReadWrite,
        (false, false) => return fail("pass --read, --write, or both"),
    };
    kinds.sort_unstable();
    kinds.dedup();
    let grant =
        Grant { app: weft_core::PublicKey::from_bytes(app.bytes())?, kinds, access, expires };
    grant.check()?;
    let record =
        sign_own(home, store, signer, |root, signer, created| grant.draft(root, signer, created))?;
    say!("{}", record.address());
    Ok(())
}

async fn grant_list(home: &Home, store: &Store) -> Result<()> {
    let root = home.root()?;
    let snap = store.snapshot()?;
    let manifest = snap.manifest(&root);
    let resolver = Resolver::new(Home::new(home.path().to_path_buf()), store.clone()).offline();
    for (record, grant) in snap.grants(&root, manifest.as_ref(), home::now()?) {
        let expiry = grant.expires.map_or(String::new(), |e| format!("  expires {e}"));
        let name = resolver.title(&grant.app).await.map_or(String::new(), |t| format!("  {t}"));
        say!(
            "{}  app {}{name}  {}  {}{expiry}",
            record.address(),
            grant.app.address(),
            grant.access,
            grant.kinds.join(",")
        );
    }
    Ok(())
}

fn grant_revoke(home: &Home, store: &Store, grant: Address, signer: &str) -> Result<()> {
    let revoke = Revoke { grant };
    let record =
        sign_own(home, store, signer, |root, signer, created| revoke.draft(root, signer, created))?;
    say!("{}", record.address());
    Ok(())
}

fn init(home: &Home) -> Result<()> {
    let meta = home.init(&home::passphrase(true)?)?;
    say!("{}", meta.public.address());
    say!("home {}", home.path().display());
    Ok(())
}

fn whoami(home: &Home) -> Result<()> {
    say!("{}  root", home.root()?.address());
    for d in home.devices()? {
        let expiry = d.expires.map_or(String::new(), |e| format!("  expires {e}"));
        say!("{}  {}  created {}{expiry}", d.public.address(), d.label, d.created);
    }
    for r in home.revoked()? {
        say!("{}  revoked", r.address());
    }
    Ok(())
}

fn key_of(address: Address) -> Result<PublicKey> {
    if address.kind() != weft_core::address::Kind::Key {
        return fail(format!("{address} is not a key address"));
    }
    Ok(PublicKey::from_bytes(address.bytes())?)
}

fn manifest(
    home: &Home,
    store: &Store,
    guardians: &[Address],
    threshold: Option<usize>,
) -> Result<()> {
    let root = home.root()?;
    let guardians = match (guardians.is_empty(), threshold) {
        (true, None) => None,
        (false, Some(threshold)) => {
            let mut keys = guardians.iter().map(|a| key_of(*a)).collect::<Result<Vec<_>>>()?;
            keys.sort_unstable();
            keys.dedup();
            Some(Guardians { keys, threshold })
        }
        _ => return fail("--guardian and --threshold go together"),
    };
    let snap = store.snapshot()?;
    let prev = snap
        .records()
        .filter(|r| r.author() == &root && r.kind() == weft_core::manifest::KIND)
        .filter_map(|r| Manifest::from_record(&r).ok().map(|m| (r.address(), m)))
        .max_by_key(|(_, m)| m.seq);
    let next =
        home.manifest(prev.as_ref().map(|(_, m)| m), prev.as_ref().map(|(a, _)| *a), guardians)?;
    let key = home.open(ROOT, &home::passphrase(false)?)?;
    let created = home::now()?;
    let record = next.draft(&root, created).sign(&key)?;
    let path = store.put(&record)?;
    let heads = snap.pointers(&root, weft_core::pointer::MANIFEST, None);
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
    say!("manifest seq {}  {}", next.seq, path.display());
    say!("pointer  seq {seq}  {}", pointer_path.display());
    if let Some(g) = &next.guardians {
        say!("guardians {} of {}", g.threshold, g.keys.len());
    }
    Ok(())
}

fn recover(home: &Home, store: &Store, command: RecoverCommand) -> Result<()> {
    match command {
        RecoverCommand::Draft { root } => recover_draft(home, store, root),
        RecoverCommand::Sign { message } => recover_sign(home, &message),
        RecoverCommand::Finish { message, sigs } => recover_finish(home, store, &message, &sigs),
    }
}

fn recover_draft(home: &Home, store: &Store, root: Address) -> Result<()> {
    let author = key_of(root)?;
    let to = home.root()?;
    let snap = store.snapshot()?;
    let head =
        snap.recovery_record(&author).and_then(|r| Recovery::from_record(&r).ok().map(|v| (r, v)));
    let message = Message {
        author,
        to,
        seq: head.as_ref().map_or(1, |(_, v)| v.seq.saturating_add(1)),
        prev: head.iter().map(|(r, _)| r.address()).collect(),
    };
    say!("recover {} to {}  seq {}", root, to.address(), message.seq);
    say!("{}", weft_core::login::to_text(&message.encode()));
    Ok(())
}

fn recover_sign(home: &Home, message: &str) -> Result<()> {
    let bytes = weft_core::login::from_text(message)?;
    let parsed = Message::decode(&bytes)?;
    let key = home.open(ROOT, &home::passphrase(false)?)?;
    let sig = key.sign_in(weft_core::recovery::DOMAIN, &bytes);
    say!("author {}", parsed.author.address());
    say!("to     {}", parsed.to.address());
    say!("seq    {}", parsed.seq);
    say!("{}{}", HEXLOWER.encode(key.public().bytes()), HEXLOWER.encode(&sig));
    Ok(())
}

fn recover_finish(home: &Home, store: &Store, message: &str, sigs: &[String]) -> Result<()> {
    let bytes = weft_core::login::from_text(message)?;
    let parsed = Message::decode(&bytes)?;
    let root = home.root()?;
    if parsed.to != root {
        return fail(format!(
            "the message names {} as the new root, this home is {}",
            parsed.to.address(),
            root.address()
        ));
    }
    let mut sigs = sigs
        .iter()
        .map(|s| {
            let raw =
                HEXLOWER.decode(s.as_bytes()).map_err(|_| "signature is not lowercase hex")?;
            if raw.len() != 96 {
                return fail("a signature is 96 bytes: the guardian key then the signature");
            }
            let key = PublicKey::from_bytes(&raw[..32].try_into().map_err(|_| "key")?)?;
            let sig: [u8; 64] = raw[32..].try_into().map_err(|_| "signature")?;
            Ok(Signature { key, sig })
        })
        .collect::<Result<Vec<_>>>()?;
    sigs.sort_by_key(|s| s.key);
    let recovery = Recovery { to: parsed.to, seq: parsed.seq, prev: parsed.prev, sigs };
    let key = home.open(ROOT, &home::passphrase(false)?)?;
    let record = recovery.draft(&parsed.author, home::now()?).sign(&key)?;
    let snap = store.snapshot()?;
    let Some(manifest) = snap.manifest(&parsed.author) else {
        return fail(format!("no manifest held for {}: fetch it first", parsed.author.address()));
    };
    verify(&record, Some(&manifest))?;
    let path = store.put(&record)?;
    say!("recovered {} to {}  {}", parsed.author.address(), root.address(), path.display());
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
        let address = Address::of(&data);
        home.keep_blob(&address, &data)?;
        Body::Blob(address)
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
    say!("{}", store.put(&record)?.display());
    Ok(())
}

fn point(home: &Home, store: &Store, name: &str, target: Address, signer: &str) -> Result<()> {
    let root = home.root()?;
    let snap = store.snapshot()?;
    let manifest = snap.manifest(&root);
    let key = home.open(signer, &home::passphrase(false)?)?;
    let pointer = next_pointer(&snap, &root, name, target);
    let record = pointer.draft(&root, &key.public(), home::now()?).sign(&key)?;
    verify(&record, manifest.as_ref())?;
    say!("{}", store.put(&record)?.display());
    Ok(())
}

fn next_pointer(snap: &Snapshot, root: &PublicKey, name: &str, target: Address) -> Pointer {
    let manifest = snap.manifest(root);
    let existing = snap.pointers(root, name, manifest.as_ref());
    let seq = existing.iter().map(|(_, p)| p.seq).max().map_or(1, |s| s.saturating_add(1));
    let prev = Store::head(&existing).map(|(r, _)| r.address()).into_iter().collect();
    Pointer { name: name.to_owned(), target, seq, prev }
}

fn verify_file(
    store: &Store,
    file: &std::path::Path,
    manifest_path: Option<&std::path::Path>,
) -> Result<()> {
    let record = read_record(file)?;
    let manifest = match manifest_path {
        Some(p) => Some(Manifest::from_record(&read_record(p)?)?),
        None if record.self_signed() => None,
        None => store.snapshot()?.manifest(record.author()),
    };
    let v = verify(&record, manifest.as_ref())?;
    say!("ok      {}", v.address);
    say!("kind    {}", v.kind);
    say!("author  {}", v.author);
    say!("signer  {}", v.signer);
    Ok(())
}

fn inspect(record: &Record) -> Result<()> {
    say!("address {}", record.address());
    say!("kind    {}", record.kind());
    say!("author  {}", record.author().address());
    say!("signer  {}", record.signer().address());
    say!("created {}", record.created());
    for r in record.refs() {
        say!("ref     {r}");
    }
    match record.body() {
        Body::Inline(b) => say!("body    {} bytes inline", b.len()),
        Body::Blob(a) => say!("blob    {a}"),
    }
    match record.kind() {
        weft_core::manifest::KIND => {
            let m = Manifest::from_record(record)?;
            say!("seq     {}", m.seq);
            for d in &m.devices {
                say!("device  {}  {}", d.key.address(), d.label);
            }
            for k in &m.revoked {
                say!("revoked {}", k.address());
            }
        }
        weft_core::pointer::KIND => {
            let p = Pointer::from_record(record)?;
            say!("name    {}", p.name);
            say!("seq     {}", p.seq);
            say!("target  {}", p.target);
        }
        weft_core::grant::KIND => {
            let g = Grant::from_record(record)?;
            say!("app     {}", g.app.address());
            say!("access  {}", g.access);
            say!("kinds   {}", g.kinds.join(","));
            if let Some(e) = g.expires {
                say!("expires {e}");
            }
        }
        weft_core::grant::REVOKE => {
            say!("grant   {}", Revoke::from_record(record)?.grant);
        }
        weft_core::receipt::KIND => {
            let r = Receipt::from_record(record)?;
            say!("relay   {}", relay_id(&r.relay)?);
            say!("until   {}", r.until);
            match &r.payment {
                Payment::Voucher(v) => {
                    say!("cents   {}", v.cents);
                    say!("bank    {}", v.bank.address());
                    say!("voucher {}", v.id());
                }
                Payment::Preimage(_) => say!("invoice {}", r.payment.id()),
            }
            for a in &r.records {
                say!("pins    {a}");
            }
        }
        weft_core::login::KIND => {
            let c = Challenge::from_record(record)?;
            say!("service {}", c.service);
            say!("expires {}", c.expires);
        }
        _ => {}
    }
    say!("sig     {}", record.check_signature().map_or("invalid", |()| "valid"));
    Ok(())
}

async fn dns(domain: &str) -> Result<()> {
    let Ok(weft_resolve::Target::Domain { host, .. }) = domain.parse() else {
        return fail("not a domain");
    };
    let doh = std::env::var(weft_resolve::resolver::DOH_ENV).ok();
    let dns = weft_resolve::Dns::new(doh.as_deref()).map_err(|e| e.to_string())?;
    let binding = dns.lookup(&host).await.map_err(|e| e.to_string())?;
    say!(
        "{}  dnssec {}",
        binding.author.address(),
        if binding.authentic { "verified" } else { "unverified" }
    );
    Ok(())
}

async fn resolve(home: &Home, store: &Store, author: Address, name: &str) -> Result<()> {
    let asked = key_of(author)?;
    let resolver = Resolver::new(Home::new(home.path().to_path_buf()), store.clone()).offline();
    let author = resolver.redirect(asked).await.map_err(|e| e.to_string())?;
    if author != asked {
        say!("recovered to {}", author.address());
    }
    let snap = store.snapshot()?;
    let manifest = snap.manifest(&author);
    let pointers = snap.pointers(&author, name, manifest.as_ref());
    let Some((record, pointer)) = Store::head(&pointers) else {
        return fail(format!("no valid pointer named {name} by {}", author.address()));
    };
    let present = snap.find(pointer.target).is_some();
    say!("{}", pointer.target);
    say!("seq {}  signer {}  pointer {}", pointer.seq, record.signer().address(), record.address());
    say!("target {}", if present { "present" } else { "absent" });
    Ok(())
}
