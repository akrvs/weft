#![forbid(unsafe_code)]

pub mod address;
pub mod cbor;
pub mod error;
pub mod follow;
pub mod grant;
pub mod identity;
pub mod label;
pub mod login;
pub mod manifest;
pub mod petname;
pub mod pointer;
pub mod receipt;
pub mod record;
pub mod recovery;
pub mod verify;

pub use address::Address;
pub use error::Error;
pub use follow::Follows;
pub use grant::{Access, Grant, Revoke};
pub use identity::{PublicKey, SecretKey};
pub use label::{Label, Labels};
pub use login::{Challenge, Login, Proof};
pub use manifest::{Device, Guardians, Manifest};
pub use petname::{Petname, Petnames};
pub use pointer::Pointer;
pub use receipt::{Payment, Receipt, Voucher};
pub use record::{Body, Draft, Record};
pub use recovery::Recovery;
pub use verify::{Verified, verify};

pub type Result<T> = core::result::Result<T, Error>;
