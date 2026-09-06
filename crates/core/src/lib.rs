#![forbid(unsafe_code)]

pub mod address;
pub mod cbor;
pub mod error;
pub mod grant;
pub mod identity;
pub mod manifest;
pub mod pointer;
pub mod record;
pub mod verify;

pub use address::Address;
pub use error::Error;
pub use grant::{Access, Grant, Revoke};
pub use identity::{PublicKey, SecretKey};
pub use manifest::{Device, Manifest};
pub use pointer::Pointer;
pub use record::{Body, Draft, Record};
pub use verify::{Verified, verify};

pub type Result<T> = core::result::Result<T, Error>;
