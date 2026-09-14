use iroh::endpoint::{Builder, RelayMode, presets};
use iroh::{Endpoint, SecretKey};
use iroh_mdns_address_lookup::MdnsAddressLookup;

use crate::{Error, Result};

pub const ENV: &str = "WEFT_NET";
pub const SERVICE: &str = "weft";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Net {
    Public,
    Local,
}

impl Net {
    pub fn parse(value: Option<&str>) -> Result<Self> {
        match value {
            None | Some("") => Ok(Self::Public),
            Some("local") => Ok(Self::Local),
            Some(other) => Err(Error::Net(format!("{ENV}={other}: expected `local` or unset"))),
        }
    }

    pub fn from_env() -> Result<Self> {
        Self::parse(std::env::var(ENV).ok().as_deref())
    }

    pub fn builder(self) -> Builder {
        match self {
            Self::Public => Endpoint::builder(presets::N0),
            Self::Local => Endpoint::builder(presets::Minimal)
                .relay_mode(RelayMode::Disabled)
                .address_lookup(MdnsAddressLookup::builder().service_name(SERVICE)),
        }
    }

    pub async fn bind(self, key: Option<SecretKey>) -> Result<Endpoint> {
        let builder = self.builder();
        let builder = match key {
            Some(key) => builder.secret_key(key),
            None => builder,
        };
        builder.bind().await.map_err(crate::error::net)
    }

    pub async fn online(self, endpoint: &Endpoint) {
        if self == Self::Public {
            endpoint.online().await;
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn unset_or_empty_is_public_and_local_is_local() {
        assert_eq!(Net::parse(None).unwrap(), Net::Public);
        assert_eq!(Net::parse(Some("")).unwrap(), Net::Public);
        assert_eq!(Net::parse(Some("local")).unwrap(), Net::Local);
    }

    #[test]
    fn any_other_value_is_an_error() {
        for bad in ["Local", "lan", "public", "0"] {
            let e = Net::parse(Some(bad)).unwrap_err().to_string();
            assert!(e.contains(bad), "{e}");
        }
    }
}
