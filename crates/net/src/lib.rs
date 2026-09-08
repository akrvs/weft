#![forbid(unsafe_code)]

pub mod client;
pub mod error;
pub mod index;
pub mod relay;
pub mod wire;

pub use client::{Client, Head, PutOutcome};
pub use error::Error;
pub use iroh::EndpointId;
pub use relay::{Pricing, Relay};

pub type Result<T> = core::result::Result<T, Error>;
