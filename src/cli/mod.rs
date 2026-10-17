//! Command-line interface: argument parsing and command dispatch.

mod account;
mod account_class;
mod account_json;
mod account_name;
mod account_reload;
mod accounts;
mod alert;
mod alias;
mod antispam;
mod api_keys;
mod app_passwords;
mod archive;
mod attachments;
mod autoconfig;
mod autodiscover;
mod backup;
mod ban;
mod completions;
mod config_check;
pub mod config_edit;
mod container_db;
mod csv;
mod db_harden;
mod db_status;
mod db_upgrade;
mod delivery;
mod disabled_domain;
mod dkim_cli;
mod dkim_show;
mod dns_provider;
mod dns_records;
mod domain;
mod evidence;
mod evidence_abandon;
mod evidence_bundle;
mod evidence_clock;
mod evidence_key;
mod evidence_policy;
mod evidence_timestamp;
mod evidence_verify;
mod exit;
mod export;
mod import;
mod init;
mod json_out;
mod legacy;
mod limits;
mod local;
mod masked;
mod migrate;
mod mobileconfig;
mod mta_sts_serve;
mod pick;
mod probe;
mod prompt;
mod queue;
mod relay;
mod report_abuse;
mod reports;
mod resource;
mod role_addresses;
mod serve;
mod serve_dkim;
mod serve_evidence;
mod serve_listeners;
mod serve_queue;
mod serve_ratelimit;
mod serve_smtp_state;
mod serve_store;
mod serve_tasks;
mod serve_tasks_delivery;
mod serve_tls;
mod service;
mod service_edit;
mod srv;
mod stack;
mod stack_dumps;
mod stack_health;
mod stack_resources;
mod stack_rollback;
mod stack_socket;
mod stack_started;
mod stack_update;
mod staging;
mod status;
mod storage_blobs;
mod style;
mod subid;
mod suppression;
mod term;
mod tls_cli;
#[cfg(test)]
pub(crate) mod tracing_capture;
mod tracing_setup;
mod util;
mod verify;
mod verify_dns;
mod warmup;
mod webhook_admin;

/// Re-export of the answers structure so integration tests can
/// deserialise the `epistle init --print-answers` output without
/// depending on the otherwise-private `init` module.
pub use {init::Answers, pick::run_from_env};

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

#[cfg(test)]
#[path = "cli_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "cli_tests_b.rs"]
mod tests_b;

#[cfg(test)]
#[path = "cli_tests_c.rs"]
mod tests_c;

#[cfg(test)]
#[path = "cli_tests_d.rs"]
mod tests_d;

#[cfg(test)]
#[path = "cli_tests_e.rs"]
mod tests_e;

#[cfg(test)]
#[path = "cli_tests_decorated.rs"]
mod cli_tests_decorated;

#[cfg(test)]
#[path = "mta_sts_serve_tests.rs"]
mod mta_sts_serve_tests;

#[cfg(test)]
#[path = "command_cases.rs"]
mod command_cases;

#[cfg(test)]
#[path = "cli_tests_config_defaults.rs"]
mod tests_config_defaults;

#[cfg(test)]
#[path = "cli_account_subcommand_tests.rs"]
mod cli_account_subcommand_tests;

#[cfg(test)]
#[path = "cli_account_subcommand_tests_b.rs"]
mod cli_account_subcommand_tests_b;

#[cfg(test)]
#[path = "cli_account_show_tests.rs"]
mod cli_account_show_tests;

#[cfg(test)]
#[path = "cli_confirmation_flow_tests.rs"]
mod cli_confirmation_flow_tests;

#[cfg(test)]
#[path = "cli_account_scram_tests.rs"]
mod cli_account_scram_tests;

#[cfg(test)]
#[path = "cli_account_resource_tests.rs"]
mod cli_account_resource_tests;

#[cfg(test)]
#[path = "cli_account_forward_catch_all_tests.rs"]
mod cli_account_forward_catch_all_tests;

#[cfg(test)]
#[path = "cli_account_catch_all_rules_tests.rs"]
mod cli_account_catch_all_rules_tests;

#[cfg(test)]
#[path = "cli_account_forward_rules_tests.rs"]
mod cli_account_forward_rules_tests;

#[cfg(test)]
#[path = "cli_account_two_factor_tests.rs"]
mod cli_account_two_factor_tests;

#[cfg(test)]
#[path = "cli_account_2fa_cli_tests.rs"]
mod cli_account_2fa_cli_tests;

#[cfg(test)]
#[path = "cli_app_password_resource_tests.rs"]
mod cli_app_password_resource_tests;

#[cfg(test)]
#[path = "cli_app_password_list_tests.rs"]
mod cli_app_password_list_tests;

#[cfg(test)]
#[path = "cli_api_key_account_tests.rs"]
mod cli_api_key_account_tests;

#[cfg(test)]
#[path = "cli_api_key_resource_tests.rs"]
mod cli_api_key_resource_tests;

#[cfg(test)]
#[path = "cli_consistency_tests.rs"]
mod cli_consistency_tests;

#[cfg(test)]
#[path = "cli_json_shape_tests.rs"]
mod cli_json_shape_tests;

#[cfg(test)]
#[path = "cli_json_everywhere_tests.rs"]
mod cli_json_everywhere_tests;

#[cfg(test)]
#[path = "cli_suppression_resource_tests.rs"]
mod cli_suppression_resource_tests;

#[cfg(test)]
#[path = "cli_account_log_id_tests.rs"]
mod cli_account_log_id_tests;

#[cfg(test)]
#[path = "cli_confirmation_tests.rs"]
mod cli_confirmation_tests;

#[cfg(test)]
#[path = "oauth_keygen_tests.rs"]
mod oauth_keygen_tests;
