//! TLS-RPT (RFC 8460) reporting for transport security.

mod https_target;
mod record;
pub mod report;
pub mod send;
pub mod sessions;

pub use record::{Record, parse};
