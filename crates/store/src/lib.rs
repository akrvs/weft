#![forbid(unsafe_code)]

pub mod client;
pub mod error;
pub mod gate;
pub mod server;
pub mod wire;

pub use client::Client;
pub use error::{Error, Result};
pub use gate::{Gate, socket_path};
pub use server::serve;
