//! Finite native networking declarations and supplied-only semantic checks.
//!
//! Native formats retain their served API, absence, null and private unknown members.
//! Offline validation does not establish API-server, controller or network behavior.
mod capabilities;
mod facts;
mod required;
pub(crate) mod roots;
mod types;
mod validation;
pub use roots::*;
pub use types::*;

pub(crate) use capabilities::source_default_enum;
