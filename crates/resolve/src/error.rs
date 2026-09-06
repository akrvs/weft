use core::fmt;

use weft_core::Address;

#[derive(Debug)]
pub enum Error {
    Core(weft_core::Error),
    Home(weft_home::Fail),
    Net(weft_net::Error),
    Dns(String),
    Target(&'static str),
    Binding(&'static str),
    NotFound(Address),
    NoPointer(String),
    Text,
}

pub type Result<T> = core::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core(e) => e.fmt(f),
            Self::Home(e) => e.fmt(f),
            Self::Net(e) => e.fmt(f),
            Self::Dns(why) => write!(f, "dns: {why}"),
            Self::Target(why) => write!(f, "target: {why}"),
            Self::Binding(why) => write!(f, "binding: {why}"),
            Self::NotFound(address) => write!(f, "{address} not found locally or on any relay"),
            Self::NoPointer(name) => write!(f, "no valid pointer named {name}"),
            Self::Text => f.write_str("page body is not utf-8"),
        }
    }
}

impl std::error::Error for Error {}

impl From<weft_core::Error> for Error {
    fn from(e: weft_core::Error) -> Self {
        Self::Core(e)
    }
}

impl From<weft_home::Fail> for Error {
    fn from(e: weft_home::Fail) -> Self {
        Self::Home(e)
    }
}

impl From<weft_net::Error> for Error {
    fn from(e: weft_net::Error) -> Self {
        Self::Net(e)
    }
}
