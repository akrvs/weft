#![forbid(unsafe_code)]

pub mod dns;
pub mod error;
pub mod render;
pub mod resolver;
pub mod target;

pub use dns::{Binding, Dns};
pub use error::{Error, Result};
pub use render::{Links, escape, render};
pub use resolver::{Page, Resolver};
pub use target::Target;
