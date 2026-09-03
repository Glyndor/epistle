//! Command-line interface: argument parsing and command dispatch.

mod accounts;
mod api_keys;
mod app_passwords;
mod archive;
mod autoconfig;
mod autodiscover;
mod backup;
mod dns_records;
mod export;
mod import;
mod mobileconfig;
mod queue;
mod report_abuse;
mod serve;
mod serve_tasks;
mod srv;
mod suppression;
#[cfg(test)]
pub(crate) mod tracing_capture;
mod tracing_setup;
mod util;
mod verify;
mod verify_dns;

use util::{generate_secret, read_line};

use std::path::PathBuf;

#[cfg(test)]
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use crate::directory_store::removal::QueuePolicy;

/// Headless mail server: SMTP, IMAP and modern email security through an
/// API and CLI.
#[derive(Debug, Parser)]
#[command(name = "epistle", version, disable_help_subcommand = true)]
pub struct Cli {
	/// The parsed subcommand. Visible to the dispatch module so the
	/// match arm there can read it without rebuilding the parser.
	#[command(subcommand)]
	pub(super) command: Command,
}

/// Every subcommand the `epistle` binary understands. Each variant
/// corresponds to a top-level entry in `epistle --help`, with its own
/// arguments; the `Cli::run` dispatch in `mod dispatch` pairs each
/// variant with the right handler module.
#[derive(Debug, Subcommand)]
pub enum Command {
	/// Run the mail server.
	Serve {
		/// Path to the configuration file.
		#[arg(long, value_name = "FILE")]
		config: PathBuf,
	},
	/// Validate a configuration file and report problems.
	ConfigCheck {
		/// Path to the configuration file.
		#[arg(long, value_name = "FILE")]
		config: PathBuf,
	},
	/// Generate an ed25519 DKIM key and print the DNS record value.
	DkimKeygen {
		/// Where to write the private key (PKCS#8 PEM).
		#[arg(long, value_name = "FILE")]
		out: PathBuf,
	},
	/// Generate a base64 32-byte at-rest message-encryption key and print it to
	/// stdout. Store it off the data disk (an env var or a key file), then point
	/// `[storage]` at it; never written into data_dir.
	StorageKeygen,
	/// Generate an ES256 key pair for the built-in OAuth authorization server and
	/// print it to stdout: the base64 PKCS#8 private key for `[oauth] signing_key`
	/// and the matching base64 public point for `[oauth] public_key`.
	OauthKeygen,
	/// Export an account's mailboxes to an mbox stream on stdout (backup), or to
	/// a Maildir tree with `--maildir`.
	Export {
		/// Path to the configuration file.
		#[arg(long, value_name = "FILE")]
		config: PathBuf,
		/// The account name to export.
		#[arg(long, value_name = "NAME")]
		account: String,
		/// Export to a Maildir directory tree instead of an mbox stream.
		#[arg(long, value_name = "DIR")]
		maildir: Option<PathBuf>,
	},
	/// Import mail into an account (migration): an mbox stream from stdin, or a
	/// Maildir tree with `--maildir`.
	Import {
		/// Path to the configuration file.
		#[arg(long, value_name = "FILE")]
		config: PathBuf,
		/// The account name to import into.
		#[arg(long, value_name = "NAME")]
		account: String,
		/// Import from a Maildir directory tree (incl. nested Dovecot folders)
		/// instead of an mbox stream on stdin.
		#[arg(long, value_name = "DIR")]
		maildir: Option<PathBuf>,
	},
	/// Write a consistent backup snapshot (gzip tar) to stdout: the filesystem
	/// mail store plus a pg_dump when a database is configured.
	Backup {
		/// Path to the configuration file.
		#[arg(long, value_name = "FILE")]
		config: PathBuf,
	},
	/// Verify on-disk data integrity (run before an upgrade).
	Verify {
		/// Path to the configuration file.
		#[arg(long, value_name = "FILE")]
		config: PathBuf,
	},
	/// Check published DNS records against what epistle expects and report
	/// drift (read-only; queries DNS, changes nothing).
	VerifyDns {
		/// Path to the configuration file.
		#[arg(long, value_name = "FILE")]
		config: PathBuf,
	},
	/// Print the DNS records this deployment should publish (SPF, DKIM, DMARC,
	/// MTA-STS, MX and a DANE TLSA record when a certificate is present).
	DnsRecords {
		/// Path to the configuration file.
		#[arg(long, value_name = "FILE")]
		config: PathBuf,
	},
	/// Print an Apple `.mobileconfig` profile for an account (for the user to
	/// install on iOS/macOS to auto-configure Mail).
	Mobileconfig {
		/// Path to the configuration file.
		#[arg(long, value_name = "FILE")]
		config: PathBuf,
		/// The account name.
		#[arg(long, value_name = "NAME")]
		account: String,
	},
	/// Print the RFC 6186 service-discovery SRV records to publish in DNS.
	SrvRecords {
		/// Path to the configuration file.
		#[arg(long, value_name = "FILE")]
		config: PathBuf,
	},
	/// Print the Thunderbird autoconfig XML for a domain (host it at
	/// `autoconfig.<domain>/mail/config-v1.1.xml`).
	Autoconfig {
		/// Path to the configuration file.
		#[arg(long, value_name = "FILE")]
		config: PathBuf,
		/// The domain (defaults to the first configured domain).
		#[arg(long, value_name = "DOMAIN")]
		domain: Option<String>,
	},
	/// Print the Microsoft Autodiscover v1 XML for a domain (host it at
	/// `autodiscover.<domain>/autodiscover/autodiscover.xml`).
	Autodiscover {
		/// Path to the configuration file.
		#[arg(long, value_name = "FILE")]
		config: PathBuf,
		/// The domain (defaults to the first configured domain).
		#[arg(long, value_name = "DOMAIN")]
		domain: Option<String>,
	},
	/// List the outbound suppression list (addresses that hard-bounced), or
	/// remove one with `--remove`.
	Suppression {
		/// Path to the configuration file.
		#[arg(long, value_name = "FILE")]
		config: PathBuf,
		/// Remove this address from the suppression list instead of listing.
		#[arg(long, value_name = "ADDRESS")]
		remove: Option<String>,
		/// Operate on this sending account's per-account list, not the global one.
		#[arg(long, value_name = "ACCOUNT")]
		account: Option<String>,
	},
	/// Read an offending message on stdin and print an RFC 5965 ARF abuse
	/// report (send it to the offending sender's abuse address).
	ReportAbuse {
		/// Path to the configuration file.
		#[arg(long, value_name = "FILE")]
		config: PathBuf,
	},
	/// List the configured mail accounts.
	Accounts {
		/// Path to the configuration file.
		#[arg(long, value_name = "FILE")]
		config: PathBuf,
	},
	/// Create a mail account, reading the password from stdin (one line).
	AccountAdd {
		/// Path to the configuration file.
		#[arg(long, value_name = "FILE")]
		config: PathBuf,
		/// The account name.
		#[arg(long, value_name = "NAME")]
		name: String,
		/// An email address for the account (repeatable).
		#[arg(long = "address", value_name = "ADDR", required = true)]
		addresses: Vec<String>,
	},
	/// Remove a dynamic account and its whole footprint (mailbox,
	/// masked addresses, app passwords, per-account suppression,
	/// queued outbound mail). `--queue` chooses what to do with mail
	/// in the outbound queue on behalf of the account: `discard` drops
	/// it, `drain` leaves it to be delivered. The choice is required:
	/// dropping mail silently is the worse default.
	AccountRemove {
		/// Path to the configuration file.
		#[arg(long, value_name = "FILE")]
		config: PathBuf,
		/// The account name.
		#[arg(long, value_name = "NAME")]
		name: String,
		/// What to do with queued outbound mail from the account:
		/// `discard` (drop it) or `drain` (leave it for delivery).
		#[arg(long = "queue", value_name = "POLICY", value_parser = accounts::parse_queue_policy)]
		queue: QueuePolicy,
	},
	/// List the outbound delivery queue.
	Queue {
		/// Path to the configuration file.
		#[arg(long, value_name = "FILE")]
		config: PathBuf,
	},
	/// Hash a bearer token for use in `[api] token_hash`.
	///
	/// Reads the plaintext token from stdin (one line). Prints a
	/// `sha256:<hex>` string to stdout, ready to paste into the config file.
	TokenHash,
	/// Create an app password for an account (a secondary IMAP/SMTP credential).
	/// The generated secret is printed once and never stored.
	AppPasswordCreate {
		/// Path to the configuration file.
		#[arg(long, value_name = "FILE")]
		config: PathBuf,
		/// The account the app password belongs to.
		#[arg(long, value_name = "NAME")]
		account: String,
		/// A label identifying this app password (e.g. "iphone").
		#[arg(long, value_name = "LABEL")]
		label: String,
		/// Optional expiry as Unix epoch seconds.
		#[arg(long, value_name = "EPOCH")]
		expires_at: Option<u64>,
		/// Optional single-CIDR client-IP allowlist (e.g. 203.0.113.0/24).
		#[arg(long, value_name = "CIDR")]
		ip_cidr: Option<String>,
	},
	/// List every account's app passwords (never the secret).
	AppPasswords {
		/// Path to the configuration file.
		#[arg(long, value_name = "FILE")]
		config: PathBuf,
	},
	/// Revoke an account's app password by label.
	AppPasswordRevoke {
		/// Path to the configuration file.
		#[arg(long, value_name = "FILE")]
		config: PathBuf,
		/// The account the app password belongs to.
		#[arg(long, value_name = "NAME")]
		account: String,
		/// The label of the app password to revoke.
		#[arg(long, value_name = "LABEL")]
		label: String,
	},
	/// Create a management API key. The generated key is printed once and never
	/// stored.
	ApiKeyCreate {
		/// Path to the configuration file.
		#[arg(long, value_name = "FILE")]
		config: PathBuf,
		/// A label identifying this API key (e.g. "ci").
		#[arg(long, value_name = "LABEL")]
		label: String,
		/// Optional expiry as Unix epoch seconds.
		#[arg(long, value_name = "EPOCH")]
		expires_at: Option<u64>,
		/// Optional single-CIDR client-IP allowlist (e.g. 203.0.113.0/24).
		#[arg(long, value_name = "CIDR")]
		ip_cidr: Option<String>,
		/// Permissions granted to this key (repeat to grant more than one:
		/// `read`, `write`, `send`, `scim`). Required at least once — an
		/// unscoped key is admin-equivalent, which is exactly what the scopes
		/// field exists to prevent.
		#[arg(
			long = "scope",
			value_name = "SCOPE",
			value_parser = api_keys::parse_scope,
		)]
		scopes: Vec<String>,
		/// Confine this key to a domain (repeat for more). Omitted, the key
		/// reaches every configured domain, which is what every key did
		/// before this option existed.
		#[arg(long = "domain", value_name = "DOMAIN")]
		domains: Vec<String>,
	},
	/// List the management API keys (never the key).
	ApiKeys {
		/// Path to the configuration file.
		#[arg(long, value_name = "FILE")]
		config: PathBuf,
	},
	/// Revoke a management API key by label.
	ApiKeyRevoke {
		/// Path to the configuration file.
		#[arg(long, value_name = "FILE")]
		config: PathBuf,
		/// The label of the API key to revoke.
		#[arg(long, value_name = "LABEL")]
		label: String,
	},
	/// Inspect and operate on the per-account expunged-message archive
	/// (`<account>/.archive/`), enabled by `[storage] deleted_retention_days`.
	/// Each subcommand targets one account.
	Archive {
		/// The archive sub-action (`list`, `restore`, `purge`).
		#[command(subcommand)]
		action: archive::Subcommand,
	},
}

mod dispatch;

#[cfg(test)]
#[path = "cli_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "cli_tests_b.rs"]
mod tests_b;

#[cfg(test)]
#[path = "cli_tests_c.rs"]
mod tests_c;
