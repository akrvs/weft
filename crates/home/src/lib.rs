#![forbid(unsafe_code)]

pub mod fail;
pub mod fs;
pub mod home;
pub mod keystore;
pub mod store;

pub use fail::{Fail, Result, fail};
pub use home::{Home, ROOT, now, passphrase};
pub use store::{Reads, Snapshot, Store, read_record};
