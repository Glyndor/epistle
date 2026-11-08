//! Hostile DNS at the resolver/evaluator boundary; no public DNS is used.
//! Run: cargo test --test hostile_dns -- --test-threads=1
//! MTA-STS is outbound policy discovery, not inbound sender authentication.

#[path = "../../common/mod.rs"]
#[allow(dead_code)]
mod common;
#[path = "../hostile_smtp/harness.rs"]
#[allow(dead_code)]
mod smtp_harness;

mod allocation;
mod harness;
mod negative;
mod payloads;
mod wire;
mod wire_cases;
