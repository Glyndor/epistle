//! Command-line interface: argument parsing and command dispatch.

mod account;
mod accounts;
mod alert;
mod alias;
mod antispam;
mod api_keys;
mod archive;
mod attachments;
mod autoconfig;
mod autodiscover;
mod backup;
mod ban;
mod completions;
pub mod config_edit;
mod csv;
mod db_upgrade;
mod delivery;
mod disabled_domain;
mod dkim;
mod dns_provider;
mod dns_records;
mod domain;
mod evidence;
mod exit;
mod export;
mod import;
mod init;
mod json_out;
mod learning;
mod legacy;
mod limits;
mod local;
mod masked;
mod migrate;
mod mobileconfig;
mod pick;
mod probe;
mod prompt;
mod queue;
mod relay;
mod reports;
mod resource;
mod role_addresses;
mod serve;
mod service;
mod srv;
mod stack;
mod staging;
mod status;
mod style;
mod subid;
mod suppression;
pub(crate) mod term;
pub(crate) mod trace;
mod ui;
mod util;
mod verify;
mod warmup;

/// Re-export of the answers structure so integration tests can
/// deserialise the `epistle init --print-answers` output without
/// depending on the otherwise-private `init` module.
pub use {init::Answers, pick::run_from_env};

/// Re-export of the catalog snapshot so integration tests can keep
/// `docs/limits.md` in lockstep with the in-process catalog without
/// pulling the catalog module into its public surface.
#[doc(hidden)]
pub use limits::catalog::docs_snapshot;

use {std::path::PathBuf, util::generate_secret};

use clap::{Parser, Subcommand};
#[cfg(test)]
use std::process::ExitCode;

const DEFAULT_CONFIG: &str = "/etc/epistle/mail.toml";

/// Headless mail server: SMTP, IMAP and email security, run by API and CLI.
#[derive(Debug, Parser)]
#[command(name = "epistle", version, disable_help_subcommand = true)]
pub struct Cli {
	/// The parsed subcommand. Visible to the dispatch module so the
	/// match arm there can read it without rebuilding the parser.
	#[command(subcommand)]
	pub(super) command: Command,
}

pub use command::Command;

mod command;
mod delegation;
mod dispatch;
mod rootless;

mod app;

mod client;

mod compose;

mod config;

mod container;

mod db;

mod mta;

mod oauth;

pub(crate) mod regular;

mod report;

mod storage;

mod tls;

mod webhook;

mod dns_lockdown;

#[cfg(test)]
mod tests;
