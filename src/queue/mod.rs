//! Outbound delivery queue: takes spooled relay mail to remote servers.

pub mod bounce;
pub mod client;
pub mod reply;
pub(crate) mod resolver;
pub mod srs;
pub mod suppression;
#[cfg(test)]
pub(crate) mod test_remote;
pub mod tls_outcome;
mod transport;
pub use transport::relay_connect;
mod worker;

pub use resolver::{Connector, MxConnector};
pub use suppression::SuppressionList;
pub use worker::Worker;
