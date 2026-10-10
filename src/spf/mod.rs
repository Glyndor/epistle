//! SPF evaluation (RFC 7208) for inbound mail.

mod dns;
mod evaluator;
mod record;

pub use dns::{DnsFailure, DnsLookup, SystemDns, system_resolver};
pub use evaluator::{SpfOutcome, check_host};
