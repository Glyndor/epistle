//! Changes to one account that a key makes by name, by the rules `epistle
//! account` follows. Today that is its storage quota.
//!
//! The routes are thin. What a value may be is the rule of the command and of
//! [`crate::directory_store`]; a route adds what only a request has: the key it
//! came with, the body it carries and the answer it owes.

mod quota;

pub(super) use quota::{clear_quota, set_quota};

/// Largest body a write takes.
pub(super) const MAX_BODY: usize = 4096;

#[cfg(test)]
mod tests;
