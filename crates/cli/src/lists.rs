use clap::Subcommand;
use weft_core::{Address, Draft, Label, Labels, Petnames, PublicKey, label, petname};
use weft_home::{Home, ROOT, Result, Store, fail, home};
use weft_resolve::Resolver;

use crate::{key_of, net, next_pointer};

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

fn local(home: &Home, store: &Store) -> Resolver<Store> {
    Resolver::new(Home::new(home.path().to_path_buf()), store.clone()).offline()
}

fn failed(e: &weft_resolve::Error) -> weft_home::Fail {
    e.to_string().into()
}

pub async fn petname(home: &Home, store: &Store, command: PetnameCommand) -> Result<()> {
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

pub async fn label(home: &Home, store: &Store, command: LabelCommand) -> Result<()> {
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
