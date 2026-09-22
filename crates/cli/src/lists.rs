use clap::Subcommand;
use weft_core::{
    Address, Draft, Follows, Label, Labels, Petnames, PublicKey, follow, label, petname,
};
use weft_home::{Home, ROOT, Result, Store, fail, home};
use weft_resolve::trust::MAX_DISTANCE;
use weft_resolve::{Resolver, Trust};

use crate::{key_of, net, next_pointer};

#[derive(Subcommand, Debug)]
pub enum Command {
    Petname {
        #[command(subcommand)]
        command: PetnameCommand,
    },
    Label {
        #[command(subcommand)]
        command: LabelCommand,
    },
    Follow {
        #[command(subcommand)]
        command: FollowCommand,
    },
    Trust {
        key: Option<Address>,
        #[arg(long)]
        refresh: bool,
    },
}

pub async fn run(home: &Home, store: &Store, command: Command) -> Result<()> {
    match command {
        Command::Petname { command } => petname(home, store, command).await,
        Command::Label { command } => label(home, store, command).await,
        Command::Follow { command } => follow(home, store, command).await,
        Command::Trust { key, refresh } => trust(home, store, key, refresh).await,
    }
}

#[derive(Subcommand, Debug)]
pub enum PetnameCommand {
    Add {
        name: String,
        key: Address,
        #[arg(long = "as", default_value = ROOT)]
        signer: String,
    },
    Remove {
        name: String,
        #[arg(long = "as", default_value = ROOT)]
        signer: String,
    },
    List {
        key: Option<Address>,
    },
    Import {
        key: Address,
        names: Vec<String>,
        #[arg(long = "as", default_value = ROOT)]
        signer: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum LabelCommand {
    Add {
        subject: Address,
        value: String,
        #[arg(long = "as", default_value = ROOT)]
        signer: String,
    },
    Remove {
        subject: Address,
        value: String,
        #[arg(long = "as", default_value = ROOT)]
        signer: String,
    },
    List {
        key: Option<Address>,
    },
}

#[derive(Subcommand, Debug)]
pub enum FollowCommand {
    Add {
        key: Address,
        #[arg(long = "as", default_value = ROOT)]
        signer: String,
    },
    Remove {
        key: Address,
        #[arg(long = "as", default_value = ROOT)]
        signer: String,
    },
    List {
        key: Option<Address>,
    },
    Import {
        key: Address,
        #[arg(long = "as", default_value = ROOT)]
        signer: String,
    },
}

fn local(home: &Home, store: &Store) -> Resolver<Store> {
    Resolver::new(Home::new(home.path().to_path_buf()), store.clone()).offline()
}

fn failed(e: &weft_resolve::Error) -> weft_home::Fail {
    e.to_string().into()
}

async fn petname(home: &Home, store: &Store, command: PetnameCommand) -> Result<()> {
    let own = || async { local(home, store).petnames().await.map_err(|e| failed(&e)) };
    match command {
        PetnameCommand::Add { name, key, signer } => {
            let key = key_of(key)?;
            let mut names = own().await?;
            if let Some(held) = names.key(&name) {
                return fail(format!("{name} already names {}", held.address()));
            }
            names.insert(&name, key)?;
            write(home, store, &signer, petname::POINTER, |a, s, t| names.draft(a, s, t))
        }
        PetnameCommand::Remove { name, signer } => {
            let mut names = own().await?;
            if !names.remove(&name) {
                return fail(format!("no petname {name}"));
            }
            write(home, store, &signer, petname::POINTER, |a, s, t| names.draft(a, s, t))
        }
        PetnameCommand::List { key: None } => {
            print_names(&own().await?);
            Ok(())
        }
        PetnameCommand::List { key: Some(key) } => {
            print_names(&theirs(home, store, key_of(key)?).await?);
            Ok(())
        }
        PetnameCommand::Import { key, names: wanted, signer } => {
            let from = theirs(home, store, key_of(key)?).await?;
            let mut names = own().await?;
            let mut added = 0usize;
            let picked: Vec<&str> = if wanted.is_empty() {
                from.names.iter().map(|p| p.name.as_str()).collect()
            } else {
                wanted.iter().map(String::as_str).collect()
            };
            for name in picked {
                let Some(key) = from.key(name) else {
                    say!("skipped {name}  not in their list");
                    continue;
                };
                if names.insert(name, key)? {
                    say!("added   {name}  {}", key.address());
                    added += 1;
                } else {
                    say!("kept    {name}  already yours");
                }
            }
            if added == 0 {
                return Ok(());
            }
            write(home, store, &signer, petname::POINTER, |a, s, t| names.draft(a, s, t))
        }
    }
}

async fn label(home: &Home, store: &Store, command: LabelCommand) -> Result<()> {
    let own = || async {
        let root = home.root()?;
        let labels = local(home, store).labels(root).await.map_err(|e| failed(&e))?;
        Ok::<_, weft_home::Fail>(labels.unwrap_or_default())
    };
    match command {
        LabelCommand::Add { subject, value, signer } => {
            let mut labels = own().await?;
            if !labels.insert(Label { subject, value: value.clone() })? {
                return fail(format!("{subject} already carries {value}"));
            }
            write(home, store, &signer, label::POINTER, |a, s, t| labels.draft(a, s, t))
        }
        LabelCommand::Remove { subject, value, signer } => {
            let mut labels = own().await?;
            if !labels.remove(&Label { subject, value: value.clone() }) {
                return fail(format!("{subject} carries no {value}"));
            }
            write(home, store, &signer, label::POINTER, |a, s, t| labels.draft(a, s, t))
        }
        LabelCommand::List { key: None } => {
            print_labels(&own().await?);
            Ok(())
        }
        LabelCommand::List { key: Some(key) } => {
            let resolver = net::resolver(home, store).await?;
            let labels = resolver.labels(key_of(key)?).await.map_err(|e| failed(&e))?;
            print_labels(&labels.unwrap_or_default());
            Ok(())
        }
    }
}

async fn follow(home: &Home, store: &Store, command: FollowCommand) -> Result<()> {
    let own = || async {
        let root = home.root()?;
        let follows = local(home, store).follows_of(root).await.map_err(|e| failed(&e))?;
        Ok::<_, weft_home::Fail>(follows.unwrap_or_default())
    };
    let theirs = |key: PublicKey| async move {
        let resolver = net::resolver(home, store).await?;
        match resolver.follows_of(key).await.map_err(|e| failed(&e))? {
            Some(follows) => Ok(follows),
            None => fail(format!("{} publishes no follows", key.address())),
        }
    };
    match command {
        FollowCommand::Add { key, signer } => {
            let key = key_of(key)?;
            let mut follows = own().await?;
            if !follows.insert(key)? {
                return fail(format!("{} is already followed", key.address()));
            }
            write(home, store, &signer, follow::POINTER, |a, s, t| follows.draft(a, s, t))
        }
        FollowCommand::Remove { key, signer } => {
            let key = key_of(key)?;
            let mut follows = own().await?;
            if !follows.remove(&key) {
                return fail(format!("{} is not followed", key.address()));
            }
            write(home, store, &signer, follow::POINTER, |a, s, t| follows.draft(a, s, t))
        }
        FollowCommand::List { key: None } => {
            print_follows(home, store, &own().await?).await;
            Ok(())
        }
        FollowCommand::List { key: Some(key) } => {
            print_follows(home, store, &theirs(key_of(key)?).await?).await;
            Ok(())
        }
        FollowCommand::Import { key, signer } => {
            let from = theirs(key_of(key)?).await?;
            let mut follows = own().await?;
            let mut added = 0usize;
            for key in &from.keys {
                if follows.insert(*key)? {
                    say!("added  {}", key.address());
                    added += 1;
                }
            }
            if added == 0 {
                return Ok(());
            }
            write(home, store, &signer, follow::POINTER, |a, s, t| follows.draft(a, s, t))
        }
    }
}

async fn trust(home: &Home, store: &Store, key: Option<Address>, refresh: bool) -> Result<()> {
    let root = home.root()?;
    let resolver = if refresh { net::resolver(home, store).await? } else { local(home, store) };
    let trust: Trust = resolver.trust(root).await.map_err(|e| failed(&e))?;
    let Some(key) = key else {
        for (distance, count) in trust.counts().iter().enumerate() {
            say!("{distance}  {count}");
        }
        say!("lists  {}", trust.lists());
        return Ok(());
    };
    let key = key_of(key)?;
    let Some(distance) = trust.distance(&key) else {
        return fail(format!("{} is not within {MAX_DISTANCE} follows", key.address()));
    };
    let names = local(home, store).petnames().await.unwrap_or_default();
    say!("{distance}");
    for step in trust.path(&key) {
        match names.name(&step) {
            Some(name) => say!("{}  {name}", step.address()),
            None => say!("{}", step.address()),
        }
    }
    Ok(())
}

async fn print_follows(home: &Home, store: &Store, follows: &Follows) {
    let names = local(home, store).petnames().await.unwrap_or_default();
    for key in &follows.keys {
        match names.name(key) {
            Some(name) => say!("{}  {name}", key.address()),
            None => say!("{}", key.address()),
        }
    }
}

async fn theirs(home: &Home, store: &Store, key: PublicKey) -> Result<Petnames> {
    let resolver = net::resolver(home, store).await?;
    match resolver.petnames_of(key).await.map_err(|e| failed(&e))? {
        Some(names) => Ok(names),
        None => fail(format!("{} publishes no petnames", key.address())),
    }
}

fn print_names(names: &Petnames) {
    for p in &names.names {
        say!("{}  {}", p.name, p.key.address());
    }
}

fn print_labels(labels: &Labels) {
    for l in &labels.labels {
        say!("{}  {}", l.value, l.subject);
    }
}

fn write(
    home: &Home,
    store: &Store,
    signer: &str,
    name: &str,
    draft: impl FnOnce(&PublicKey, &PublicKey, u64) -> Draft,
) -> Result<()> {
    let root = home.root()?;
    let key = home.open(signer, &home::passphrase(false)?)?;
    let now = home::now()?;
    let snap = store.snapshot()?;
    let manifest = snap.manifest(&root);
    let list = draft(&root, &key.public(), now).sign(&key)?;
    weft_core::verify(&list, manifest.as_ref())?;
    let pointer = next_pointer(&snap, &root, name, list.address())
        .draft(&root, &key.public(), now)
        .sign(&key)?;
    weft_core::verify(&pointer, manifest.as_ref())?;
    store.put(&list)?;
    store.put(&pointer)?;
    say!("{}", list.address());
    say!("{}", pointer.address());
    Ok(())
}
