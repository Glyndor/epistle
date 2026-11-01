//! External cryptographic vectors against the in-process DKIM and ARC APIs.
//! Run: cargo test --locked --test hostile_dkim -- --test-threads=2

#[path = "hostile_dkim/arc_chain.rs"]
mod arc_chain;
#[path = "hostile_dkim/arc_crypto.rs"]
mod arc_crypto;
#[path = "hostile_dkim/attacks.rs"]
mod attacks;
#[path = "hostile_dkim/canonicalization.rs"]
mod canonicalization;
#[path = "hostile_dkim/harness.rs"]
mod harness;
#[path = "hostile_dkim/keys.rs"]
mod keys;
#[path = "hostile_dkim/resources.rs"]
mod resources;
#[path = "hostile_dkim/rfc8463.rs"]
mod rfc8463;
#[path = "hostile_dkim/signer.rs"]
mod signer;
#[path = "hostile_dkim/support.rs"]
mod support;
#[path = "hostile_dkim/tags.rs"]
mod tags;
