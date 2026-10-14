//! `epistle migrate`: move an existing mail service into this one.
//!
//! `imap` copies a remote account's mail over IMAP and can be run again for
//! an incremental top-up. The other sources import configuration (domains,
//! accounts, aliases, DKIM keys) and point at `imap` for the mail itself.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Subcommand};

#[path = "migrate_config.rs"]
mod config;
#[path = "migrate_imap.rs"]
mod imap;
#[path = "migrate_imap_report.rs"]
mod report;

/// Arguments of `epistle migrate`.
#[derive(Debug, Args)]
pub struct MigrateArgs {
	/// Configuration file; accepted before or after the action.
	#[arg(long, value_name = "FILE", global = true, default_value = super::DEFAULT_CONFIG)]
	pub config: PathBuf,
	/// What to migrate from (`imap`, `mox`, `stalwart`).
	#[command(subcommand)]
	pub action: MigrateCli,
}

/// Where `epistle migrate` reads from.
#[derive(Debug, Subcommand)]
pub enum MigrateCli {
	/// Copy every folder of a remote IMAP account into a local account.
	///
	/// Implicit TLS on port 993 by default; `--starttls` upgrades a port 143
	/// connection first. The remote password is read from `--password-file`
	/// or stdin, never from the command line. Progress is kept per local
	/// account and remote folder, so running the same command again copies
	/// only what arrived since, and an interrupted run resumes.
	Imap(ImapArgs),
	/// Import domains, accounts, aliases and DKIM keys from Mox.
	///
	/// Reads `mox.conf` and `domains.conf` from the Mox configuration
	/// directory. DKIM keys keep their selectors, so DNS does not change.
	/// Passwords cannot be carried over: accounts are created disabled for
	/// login. Existing domains, accounts and aliases are never overwritten.
	Mox {
		/// The Mox configuration directory (holding mox.conf), or mox.conf.
		#[arg(long, value_name = "DIR")]
		from: PathBuf,
		/// What to do with passwords, and how to run.
		#[command(flatten)]
		import: config::ImportArgs,
	},
	/// Import domains, DKIM keys, accounts and aliases from Stalwart.
	///
	/// Reads a Stalwart config.toml (the format up to v0.15). DKIM signatures
	/// come with their selectors; accounts and aliases come when the
	/// directory is the in-file `memory` type, and the output says how to
	/// move the rest. From v0.16 Stalwart keeps every setting in its
	/// database, and that bootstrap file is refused with directions.
	Stalwart {
		/// Stalwart's config.toml.
		#[arg(long, value_name = "FILE")]
		from: PathBuf,
		/// What to do with passwords, and how to run.
		#[command(flatten)]
		import: config::ImportArgs,
	},
}

/// Arguments of `epistle migrate imap`.
#[derive(Debug, Args)]
pub struct ImapArgs {
	/// The local account the mail goes into (must exist).
	#[arg(long, value_name = "NAME", value_parser = super::account_name::parse)]
	pub account: String,
	/// The remote IMAP server's host name (also the name its certificate
	/// must carry).
	#[arg(long, value_name = "HOST")]
	pub host: String,
	/// The remote port. Default 993, or 143 with `--starttls` or
	/// `--insecure-plaintext`.
	#[arg(long, value_name = "PORT")]
	pub port: Option<u16>,
	/// The remote login name.
	#[arg(long, value_name = "USER")]
	pub user: String,
	/// Read the remote password from the first line of this file (keep it
	/// mode 0600). Without it the password is read from stdin.
	#[arg(long, value_name = "FILE")]
	pub password_file: Option<PathBuf>,
	/// Connect in plaintext and upgrade with STARTTLS before logging in.
	#[arg(long, conflicts_with = "insecure_plaintext")]
	pub starttls: bool,
	/// Send the password and mail unencrypted. Only for a server on a
	/// trusted network that offers no TLS at all.
	#[arg(long)]
	pub insecure_plaintext: bool,
	/// Do not check the server certificate. The connection is encrypted but
	/// anyone on the path can impersonate the server and read the password.
	#[arg(long, conflicts_with = "insecure_plaintext")]
	pub insecure_skip_verify: bool,
	/// Also trust the certificates in this PEM file (a private CA or a
	/// self-signed server certificate).
	#[arg(long, value_name = "FILE", conflicts_with = "insecure_plaintext")]
	pub ca_file: Option<PathBuf>,
	/// Copy only matching folders; repeatable. `*` matches anything, a
	/// leading `!` excludes (`--folders '*' --folders '!Trash'`).
	#[arg(long, value_name = "PATTERN")]
	pub folders: Vec<String>,
	/// List what would be copied, folder by folder; change nothing.
	#[arg(long)]
	pub dry_run: bool,
	/// Print the summary as one JSON object on stdout.
	#[arg(long)]
	pub json: bool,
}

/// Run one `migrate` action.
pub(super) fn run(args: MigrateArgs) -> ExitCode {
	match args.action {
		MigrateCli::Imap(imap_args) => imap::run(&args.config, imap_args),
		MigrateCli::Mox { from, import } => {
			let plan = crate::migrate::mox::read(&from).map_err(|error| error.to_string());
			config::run(&args.config, shown(plan), &import)
		}
		MigrateCli::Stalwart { from, import } => {
			let plan = crate::migrate::stalwart::read(&from).map_err(|error| error.to_string());
			config::run(&args.config, shown(plan), &import)
		}
	}
}

/// The plan as the operator reads it: a root run reads a staged copy of
/// the source, and the messages name the path the operator gave.
fn shown(
	plan: Result<crate::migrate::import::Plan, String>,
) -> Result<crate::migrate::import::Plan, String> {
	use super::staging::shown;
	match plan {
		Ok(mut plan) => {
			plan.source = shown(&plan.source);
			for note in &mut plan.skipped {
				note.reason = shown(&note.reason);
			}
			Ok(plan)
		}
		Err(error) => Err(shown(&error)),
	}
}
