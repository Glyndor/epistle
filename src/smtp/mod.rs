//! SMTP protocol implementation (RFC 5321).
//!
//! `command` parses client commands, `reply` renders server replies, and
//! `session` drives the per-connection state machine.

pub mod address;
pub mod auth;
pub mod command;
pub mod directory;
pub mod diskspace;
pub(crate) mod identification;
mod inbound_headers;
pub mod line;
pub mod memory_budget;
pub mod memory_fit;
pub mod per_ip;
pub mod quota;
pub mod ratelimit;
pub mod reply;
pub mod scram;
pub mod server;
pub mod session;
pub mod session_log;
pub mod sink;
pub mod submission_budget;
#[cfg(test)]
pub mod tests;
pub mod trace;
