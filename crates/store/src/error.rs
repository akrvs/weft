use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Core(weft_core::Error),
    Wire(&'static str),
    Io(String),
    Home(String),
    Refused(&'static str),
    Remote(String),
}

pub type Result<T> = core::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core(e) => e.fmt(f),
            Self::Wire(why) => write!(f, "wire: {why}"),
            Self::Io(why) => write!(f, "io: {why}"),
            Self::Home(why) => write!(f, "home: {why}"),
            Self::Refused(why) => write!(f, "refused: {why}"),
            Self::Remote(why) => write!(f, "store: {why}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<weft_core::Error> for Error {
    fn from(e: weft_core::Error) -> Self {
        Self::Core(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

impl From<weft_home::Fail> for Error {
    fn from(e: weft_home::Fail) -> Self {
        Self::Home(e.to_string())
    }
}
