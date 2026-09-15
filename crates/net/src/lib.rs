#![forbid(unsafe_code)]

pub mod client;
pub mod endpoint;
pub mod error;
pub mod index;
pub mod node;
pub mod relay;
pub mod wire;

pub use client::{Client, Head, Offer, PutOutcome, Quote};
pub use endpoint::Net;
pub use error::Error;
pub use iroh::EndpointId;
pub use node::{Fake, Invoice, Node};
pub use relay::{Config, Pricing, Relay};

pub type Result<T> = core::result::Result<T, Error>;
