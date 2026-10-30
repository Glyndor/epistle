//! MTA-STS (RFC 8461) policy discovery and enforcement for outbound mail.

mod policy;
pub mod publish;
pub mod server;

pub use policy::{Mode, Policy, PolicyError, PolicyFetcher, PolicyStore, SystemFetcher};

/// The policy file parser, for the fuzz target in `crate::fuzzing`.
pub(crate) use policy::parse as parse_policy;
