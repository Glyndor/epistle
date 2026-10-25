//! POP3 retrieval protocol (RFC 1939).
//!
//! Opt-in, disabled by default. `command` parses client commands; the session
//! and network layers build on it.

pub mod backend;
pub mod bounds;
pub mod command;
pub mod server;
pub mod session;

#[cfg(test)]
mod session_tests;

#[cfg(test)]
mod session_tests_termination;

#[cfg(test)]
mod session_tests_on_demand;

#[cfg(test)]
mod session_tests_gate_busy;

#[cfg(test)]
mod session_tests_per_account;

#[cfg(test)]
mod session_tests_ban_owner_known_network;
