use core::str::FromStr;

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
    fn junk_is_rejected() {
        assert!(matches!("".parse::<Target>(), Err(Error::Target("empty"))));
        assert!(matches!("/home".parse::<Target>(), Err(Error::Target("empty"))));
        assert!(matches!("notanaddress".parse::<Target>(), Err(Error::Core(_))));
        assert!(matches!(
            "https://example.com".parse::<Target>(),
            Err(Error::Target("name characters"))
        ));
    }
}
