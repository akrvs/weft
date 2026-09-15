use std::fmt;
use std::net::SocketAddr;
use std::str::FromStr;

use iroh::{EndpointAddr, EndpointId};

use crate::fail::Fail;

pub const MAX_ADDRS: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relay {
    pub id: EndpointId,
    pub addrs: Vec<SocketAddr>,
}

impl Relay {
    pub fn from_key(key: &weft_core::PublicKey) -> Result<Self, Fail> {
        let id = EndpointId::from_bytes(key.bytes()).map_err(|e| Fail(format!("relay id: {e}")))?;
        Ok(Self { id, addrs: Vec::new() })
    }

    pub fn is_key(&self, key: &weft_core::PublicKey) -> bool {
        self.id.as_bytes() == key.bytes()
    }
}

impl FromStr for Relay {
    type Err = Fail;

    fn from_str(text: &str) -> Result<Self, Fail> {
        let (id, rest) = text.split_once('@').map_or((text, None), |(i, a)| (i, Some(a)));
        let id = id.parse::<EndpointId>().map_err(|e| Fail(format!("relay id: {e}")))?;
        let mut addrs = Vec::new();
        for part in rest.into_iter().flat_map(|a| a.split(',')) {
            let addr = part
                .parse::<SocketAddr>()
                .map_err(|_| Fail(format!("relay address `{part}`: expected host:port")))?;
            if addr.port() == 0 || addr.ip().is_unspecified() {
                return Err(Fail(format!("relay address `{part}`: unusable")));
            }
            if !addrs.contains(&addr) {
                addrs.push(addr);
            }
        }
        if addrs.len() > MAX_ADDRS {
            return Err(Fail(format!("relay entry lists more than {MAX_ADDRS} addresses")));
        }
        Ok(Self { id, addrs })
    }
}

impl fmt::Display for Relay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.id)?;
        for (i, addr) in self.addrs.iter().enumerate() {
            f.write_str(if i == 0 { "@" } else { "," })?;
            write!(f, "{addr}")?;
        }
        Ok(())
    }
}

impl From<Relay> for EndpointAddr {
    fn from(relay: Relay) -> Self {
        relay.addrs.iter().fold(Self::new(relay.id), |a, addr| a.with_ip_addr(*addr))
    }
}

impl From<&Relay> for EndpointAddr {
    fn from(relay: &Relay) -> Self {
        relay.clone().into()
    }
}

impl From<EndpointAddr> for Relay {
    fn from(addr: EndpointAddr) -> Self {
        Self { id: addr.id, addrs: addr.ip_addrs().copied().take(MAX_ADDRS).collect() }
    }
}
