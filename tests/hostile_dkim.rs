//! External cryptographic vectors against the in-process DKIM and ARC APIs.
//! Run: cargo test --locked --test hostile_dkim -- --test-threads=2
//! Ignored cases specify missing defenses or conformance, not accepted behavior.

#[path = "hostile_dkim/harness.rs"]
mod harness;
#[path = "hostile_dkim/keys.rs"]
mod keys;
