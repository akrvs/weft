use core::fmt;

#[derive(Debug)]
pub struct Fail(pub String);

pub type Result<T> = core::result::Result<T, Fail>;

impl fmt::Display for Fail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Fail {}

impl From<std::io::Error> for Fail {
    fn from(e: std::io::Error) -> Self {
        Self(e.to_string())
    }
}

impl From<weft_core::Error> for Fail {
    fn from(e: weft_core::Error) -> Self {
        Self(e.to_string())
    }
}

impl From<&str> for Fail {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

impl From<String> for Fail {
    fn from(s: String) -> Self {
        Self(s)
    }
}

pub fn fail<T>(msg: impl Into<String>) -> Result<T> {
    Err(Fail(msg.into()))
}
