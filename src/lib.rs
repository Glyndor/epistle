//! Glyndor mail server library.
//!
//! Headless mail server: SMTP, IMAP and modern email security, exposed
//! through an API and a CLI. This crate hosts all server logic; the binary
//! in `main.rs` is a thin entry point.

// Every public item carries a doc comment as of #753, and this keeps it that
// way. Declared here rather than as a CI flag so it fails at the desk, in the
// same compile that introduced the gap, instead of ten minutes later in a job
// the author has stopped watching.
#![deny(missing_docs)]

pub mod acme;
pub mod alerts;
pub mod antispam;
pub mod api;
pub mod arc;
pub mod autodiscovery;
pub mod cidr;
pub mod cli;
pub mod clock;
pub mod config;
pub mod dane;
pub mod db;
pub mod directory_store;
pub mod dkim;
pub mod dmarc;
pub mod dns;
pub mod dnsbl;
pub mod imap;
pub mod jwt;
pub mod managesieve;
pub mod metrics;
pub mod mtasts;
pub mod oauth;
pub mod password;
pub mod pop3;
pub mod privdrop;
pub mod queue;
pub mod rules;
pub mod sasl;
pub mod sieve;
pub mod smtp;
pub mod spf;
pub mod storage;
pub mod tls;
pub mod tlsrpt;
pub mod totp;
pub mod util;
pub mod webdav;
pub mod webhook;
