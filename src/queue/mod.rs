//! Outbound delivery queue: takes spooled relay mail to remote servers.

pub mod backoff;
pub mod bounce;
pub mod cancel;
pub mod client;
pub mod destination;
pub mod limits;
pub mod reply;
pub(crate) mod resolver;
pub mod schedule;
pub mod srs;
pub mod suppression;
#[cfg(test)]
pub(crate) mod test_remote;
pub mod timeouts;
pub mod tls_outcome;
pub(crate) mod tls_required;
mod transport;
pub mod warmup;
pub use transport::relay_connect;
mod worker;

pub use resolver::{Connector, MxConnector};
pub use schedule::RetrySchedule;
pub use suppression::{Suppressed, SuppressionList};
pub use worker::Worker;
