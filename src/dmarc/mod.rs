//! DMARC policy evaluation (RFC 7489) for inbound mail.

pub mod aggregate;
pub mod author;
mod evaluate;
mod record;
pub mod report;

pub use evaluate::{DmarcOutcome, evaluate, from_domain};
