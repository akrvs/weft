use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Encoding(&'static str),
    Address(&'static str),
    Field(&'static str),
    Key,
    Signature,
    Unauthorized,
    Revoked,
    Expired,
    Limit(&'static str),
    Login(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encoding(why) => write!(f, "encoding: {why}"),
            Self::Address(why) => write!(f, "address: {why}"),
            Self::Field(name) => write!(f, "field: {name}"),
            Self::Key => f.write_str("key rejected"),
            Self::Signature => f.write_str("signature invalid"),
            Self::Unauthorized => f.write_str("signer not authorized by manifest"),
            Self::Revoked => f.write_str("signer revoked"),
            Self::Expired => f.write_str("signer key outside its validity window"),
            Self::Limit(what) => write!(f, "limit exceeded: {what}"),
            Self::Login(why) => write!(f, "login: {why}"),
        }
    }
}

impl std::error::Error for Error {}
