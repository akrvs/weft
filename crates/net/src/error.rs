use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Core(weft_core::Error),
    Wire(&'static str),
    Net(String),
    Store(String),
    Refused(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core(e) => e.fmt(f),
            Self::Wire(why) => write!(f, "wire: {why}"),
            Self::Net(why) => write!(f, "network: {why}"),
            Self::Store(why) => write!(f, "store: {why}"),
            Self::Refused(why) => write!(f, "refused: {why}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<weft_core::Error> for Error {
    fn from(e: weft_core::Error) -> Self {
        Self::Core(e)
    }
}

impl From<redb::Error> for Error {
    fn from(e: redb::Error) -> Self {
        Self::Store(e.to_string())
    }
}

impl From<redb::DatabaseError> for Error {
    fn from(e: redb::DatabaseError) -> Self {
        Self::Store(e.to_string())
    }
}

impl From<redb::TransactionError> for Error {
    fn from(e: redb::TransactionError) -> Self {
        Self::Store(e.to_string())
    }
}

impl From<redb::TableError> for Error {
    fn from(e: redb::TableError) -> Self {
        Self::Store(e.to_string())
    }
}

impl From<redb::StorageError> for Error {
    fn from(e: redb::StorageError) -> Self {
        Self::Store(e.to_string())
    }
}

impl From<redb::CommitError> for Error {
    fn from(e: redb::CommitError) -> Self {
        Self::Store(e.to_string())
    }
}

pub fn net(e: impl fmt::Display) -> Error {
    Error::Net(e.to_string())
}
