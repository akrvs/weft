use core::str::FromStr;

use weft_core::petname::valid_petname;
use weft_core::pointer::MAX_NAME;
use weft_core::{Address, PublicKey, address::Kind};

use crate::error::{Error, Result};

pub const HOME: &str = "home";
pub const MAX_DOMAIN: usize = 253;
pub const MAX_LABEL: usize = 63;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Address(Address),
    Named { author: PublicKey, name: String },
    Domain { host: String, name: String },
    Petname { petname: String, name: String },
}

impl FromStr for Target {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        let input = input.trim();
        let input = input.strip_prefix("weft:").unwrap_or(input);
        let (head, name) = match input.split_once('/') {
            Some((head, name)) => (head, Some(check_name(name)?)),
            None => (input, None),
        };
        if head.is_empty() {
            return Err(Error::Target("empty"));
        }
        if head.contains('.') {
            let host = domain(head)?;
            return Ok(Self::Domain { host, name: name.unwrap_or(HOME).to_owned() });
        }
        if valid_petname(head) {
            return Ok(Self::Petname {
                petname: head.to_owned(),
                name: name.unwrap_or(HOME).to_owned(),
            });
        }
        let address: Address = head.parse()?;
        match name {
            None => Ok(Self::Address(address)),
            Some(name) => {
                if address.kind() != Kind::Key {
                    return Err(Error::Target("author must be a key address"));
                }
                let author = PublicKey::from_bytes(address.bytes())?;
                Ok(Self::Named { author, name: name.to_owned() })
            }
        }
    }
}

impl core::fmt::Display for Target {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Address(address) => write!(f, "{address}"),
            Self::Named { author, name } => write!(f, "{}/{name}", author.address()),
            Self::Domain { host, name } if name == HOME => f.write_str(host),
            Self::Domain { host, name } => write!(f, "{host}/{name}"),
            Self::Petname { petname, name } if name == HOME => f.write_str(petname),
            Self::Petname { petname, name } => write!(f, "{petname}/{name}"),
        }
    }
}

fn check_name(name: &str) -> Result<&str> {
    if name.is_empty() || name.len() > MAX_NAME {
        return Err(Error::Target("name length"));
    }
    if name.contains(|c: char| c == '/' || c.is_control()) {
        return Err(Error::Target("name characters"));
    }
    Ok(name)
}

fn domain(head: &str) -> Result<String> {
    let host = head.to_ascii_lowercase();
    let host = host.strip_suffix('.').unwrap_or(&host);
    if host.len() > MAX_DOMAIN || !host.split('.').all(label) {
        return Err(Error::Target("not a domain"));
    }
    Ok(host.to_owned())
}

fn label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= MAX_LABEL
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn key() -> (PublicKey, String) {
        let key = weft_core::SecretKey::from_seed([7; 32]).public();
        let address = key.address().to_string();
        (key, address)
    }

    #[test]
    fn raw_address() {
        let (key, address) = key();
        assert_eq!(address.parse::<Target>().unwrap(), Target::Address(key.address()));
        assert_eq!(
            format!("weft:{address}").parse::<Target>().unwrap(),
            Target::Address(key.address())
        );
        let hash = Address::of(b"x");
        assert_eq!(hash.to_string().parse::<Target>().unwrap(), Target::Address(hash));
    }

    #[test]
    fn author_and_name() {
        let (key, address) = key();
        assert_eq!(
            format!("{address}/blog").parse::<Target>().unwrap(),
            Target::Named { author: key, name: "blog".to_owned() }
        );
        let hash = Address::of(b"x");
        assert!(matches!(
            format!("{hash}/blog").parse::<Target>(),
            Err(Error::Target("author must be a key address"))
        ));
        assert!(matches!(
            format!("{address}/").parse::<Target>(),
            Err(Error::Target("name length"))
        ));
        assert!(matches!(
            format!("{address}/{}", "n".repeat(MAX_NAME + 1)).parse::<Target>(),
            Err(Error::Target("name length"))
        ));
        assert!(matches!(
            format!("{address}/a/b").parse::<Target>(),
            Err(Error::Target("name characters"))
        ));
        assert!(matches!(
            format!("{address}/a\nb").parse::<Target>(),
            Err(Error::Target("name characters"))
        ));
    }

    #[test]
    fn domains() {
        assert_eq!(
            "Example.COM".parse::<Target>().unwrap(),
            Target::Domain { host: "example.com".to_owned(), name: HOME.to_owned() }
        );
        assert_eq!(
            "blog.example.com./posts".parse::<Target>().unwrap(),
            Target::Domain { host: "blog.example.com".to_owned(), name: "posts".to_owned() }
        );
        for bad in [
            "-a.com",
            "a-.com",
            "a..com",
            ".com",
            "a.com.b_c",
            "ex ample.com",
            "xn--ü.com",
            &format!("{}.com", "a".repeat(MAX_LABEL + 1)),
            &format!("{}.com", ["abcdefgh"; 32].join(".")),
        ] {
            assert!(matches!(bad.parse::<Target>(), Err(Error::Target("not a domain"))), "{bad}");
        }
    }

    #[test]
    fn the_text_form_round_trips() {
        let (_, address) = key();
        for text in [
            address.as_str(),
            &format!("{address}/blog"),
            "example.com",
            "example.com/posts",
            "alice",
            "bob-2/posts",
        ] {
            let target: Target = text.parse().unwrap();
            assert_eq!(target.to_string(), text);
            assert_eq!(target.to_string().parse::<Target>().unwrap(), target);
        }
        assert_eq!("Example.COM./home".parse::<Target>().unwrap().to_string(), "example.com");
    }

    #[test]
    fn petnames() {
        let pet = |p: &str, n: &str| Target::Petname { petname: p.to_owned(), name: n.to_owned() };
        assert_eq!("alice".parse::<Target>().unwrap(), pet("alice", HOME));
        assert_eq!("weft:alice/blog".parse::<Target>().unwrap(), pet("alice", "blog"));
        assert_eq!("a".repeat(32).parse::<Target>().unwrap(), pet(&"a".repeat(32), HOME));
        assert!(matches!("alice.example".parse::<Target>().unwrap(), Target::Domain { .. }));
        assert!(matches!(key().1.parse::<Target>().unwrap(), Target::Address(_)));
        assert!(matches!("alice/".parse::<Target>(), Err(Error::Target("name length"))));
    }

    #[test]
    fn junk_is_rejected() {
        assert!(matches!("".parse::<Target>(), Err(Error::Target("empty"))));
        assert!(matches!("/home".parse::<Target>(), Err(Error::Target("empty"))));
        assert!(matches!("Not_a_petname".parse::<Target>(), Err(Error::Core(_))));
        assert!(matches!("1alice".parse::<Target>(), Err(Error::Core(_))));
        assert!(matches!("a".repeat(33).parse::<Target>(), Err(Error::Core(_))));
        assert!(matches!(
            "https://example.com".parse::<Target>(),
            Err(Error::Target("name characters"))
        ));
    }
}
