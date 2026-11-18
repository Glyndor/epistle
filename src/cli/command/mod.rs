//! The `epistle` subcommands, one variant per top-level entry in
//! `epistle --help`. Kept apart from `cli/mod.rs` so the module index stays
//! small.

mod account_delivery;
mod administration;
mod definition;
mod deployment;
mod discovery;
mod keys;
mod mail_data;
mod operations;
mod server;
mod setup;

pub use definition::Command;

#[cfg(test)]
pub(super) mod tests;
