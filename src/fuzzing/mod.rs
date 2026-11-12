//! Entry points for the cargo-fuzz targets under `fuzz/`.
//!
//! Not an API. The parsers worth fuzzing sit behind crate-private
//! modules; these functions reach them without making those modules
//! public, and each one runs every consumer of the same untrusted bytes
//! so a target covers the whole path a hostile message or command takes.

mod backup;
mod common;
mod config;
mod dns;
mod mailbox;
mod message;
mod migrate;
mod queue;
mod scram_client;
mod smtp;
mod web;
pub use backup::backup_tar;
pub use config::config_parse;
pub use dns::{dns_security_records, report_payload, sender_auth_records};
pub use mailbox::imap_command_line;
pub use message::{
	arc_headers, arf_report, attachment_inspect, attachment_walk, dkim_signature, mime, rules_match,
};
pub use migrate::migrate_imap_response;
pub use queue::srs_reverse;
pub use smtp::{sasl_exchange, smtp_bdat, smtp_reply};
pub use web::{jwt_decode, webdav_filter_rrule, webdav_report_body};
