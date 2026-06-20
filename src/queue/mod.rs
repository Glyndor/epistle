//! Outbound delivery queue: takes spooled relay mail to remote servers.

pub mod bounce;
pub mod client;
mod resolver;
pub mod srs;
pub mod suppression;
mod worker;

pub use resolver::{Connector, MxConnector};
pub use suppression::SuppressionList;
pub use worker::Worker;
