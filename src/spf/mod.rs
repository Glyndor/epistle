//! SPF evaluation (RFC 7208) for inbound mail.

mod dns;
mod evaluator;
pub(crate) use evaluator::{MAX_DNS_MECHANISMS, MAX_VOID_LOOKUPS};
mod record;

pub use dns::{DnsFailure, DnsLookup, SrvRecord, SystemDns, system_resolver};
pub use evaluator::{SpfOutcome, check_host};
