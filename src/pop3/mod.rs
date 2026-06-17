//! POP3 retrieval protocol (RFC 1939).
//!
//! Opt-in, disabled by default. `command` parses client commands; the session
//! and network layers build on it.

pub mod command;
pub mod session;

#[cfg(test)]
mod session_tests;
