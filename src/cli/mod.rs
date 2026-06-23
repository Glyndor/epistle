//! Command-line interface: argument parsing and command dispatch.

mod accounts;
mod api_keys;
mod app_passwords;
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
mod tracing_setup;
mod util;
mod verify;
mod verify_dns;

use util::{dkim_keygen, generate_secret, read_line, token_hash};

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use crate::config::Config;

/// Headless mail server: SMTP, IMAP and modern email security through an
/// API and CLI.
#[derive(Debug, Parser)]
#[command(name = "epistle", version, disable_help_subcommand = true)]
pub struct Cli {
	#[command(subcommand)]
	command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
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
}

impl Cli {
	/// Execute the parsed command.
	pub fn run(self) -> ExitCode {
		match self.command {
			Command::Serve { config } => match Config::load(&config) {
				Ok(config) => serve::run(config),
				Err(error) => {
					eprintln!("error: {error}");
					ExitCode::FAILURE
				}
			},
			Command::ConfigCheck { config } => match Config::load(&config) {
				Ok(_) => {
					println!("configuration is valid");
					ExitCode::SUCCESS
				}
				Err(error) => {
					eprintln!("error: {error}");
					ExitCode::FAILURE
				}
			},
			Command::Export {
				config,
				account,
				maildir,
			} => match Config::load(&config) {
				Ok(config) => match maildir {
					Some(dir) => export::run_maildir(&config.data_dir, &account, &dir),
					None => export::run(&config.data_dir, &account, &mut std::io::stdout().lock()),
				},
				Err(error) => {
					eprintln!("error: {error}");
					ExitCode::FAILURE
				}
			},
			Command::Import {
				config,
				account,
				maildir,
			} => match Config::load(&config) {
				Ok(config) => match maildir {
					Some(dir) => import::run_maildir(&config.data_dir, &account, &dir),
					None => import::run(&config.data_dir, &account, std::io::stdin().lock()),
				},
				Err(error) => {
					eprintln!("error: {error}");
					ExitCode::FAILURE
				}
			},
			Command::Backup { config } => match Config::load(&config) {
				Ok(config) => backup::run(&config, &mut std::io::stdout().lock()),
				Err(error) => {
					eprintln!("error: {error}");
					ExitCode::FAILURE
				}
			},
			Command::Verify { config } => match Config::load(&config) {
				Ok(config) => verify::run(&config.data_dir, &mut std::io::stdout().lock()),
				Err(error) => {
					eprintln!("error: {error}");
					ExitCode::FAILURE
				}
			},
			Command::VerifyDns { config } => match Config::load(&config) {
				Ok(config) => verify_dns::run(&config, &mut std::io::stdout().lock()),
				Err(error) => {
					eprintln!("error: {error}");
					ExitCode::FAILURE
				}
			},
			Command::DnsRecords { config } => match Config::load(&config) {
				Ok(config) => dns_records::run(&config, &mut std::io::stdout().lock()),
				Err(error) => {
					eprintln!("error: {error}");
					ExitCode::FAILURE
				}
			},
			Command::Mobileconfig { config, account } => match Config::load(&config) {
				Ok(config) => mobileconfig::run(&config, &account, &mut std::io::stdout().lock()),
				Err(error) => {
					eprintln!("error: {error}");
					ExitCode::FAILURE
				}
			},
			Command::SrvRecords { config } => match Config::load(&config) {
				Ok(config) => srv::run(&config, &mut std::io::stdout().lock()),
				Err(error) => {
					eprintln!("error: {error}");
					ExitCode::FAILURE
				}
			},
			Command::Autoconfig { config, domain } => match Config::load(&config) {
				Ok(config) => {
					autoconfig::run(&config, domain.as_deref(), &mut std::io::stdout().lock())
				}
				Err(error) => {
					eprintln!("error: {error}");
					ExitCode::FAILURE
				}
			},
			Command::Suppression {
				config,
				remove,
				account,
			} => match Config::load(&config) {
				Ok(config) => suppression::run(
					&config,
					remove.as_deref(),
					account.as_deref(),
					&mut std::io::stdout().lock(),
				),
				Err(error) => {
					eprintln!("error: {error}");
					ExitCode::FAILURE
				}
			},
			Command::Autodiscover { config, domain } => match Config::load(&config) {
				Ok(config) => {
					autodiscover::run(&config, domain.as_deref(), &mut std::io::stdout().lock())
				}
				Err(error) => {
					eprintln!("error: {error}");
					ExitCode::FAILURE
				}
			},
			Command::ReportAbuse { config } => match Config::load(&config) {
				Ok(config) => report_abuse::run(
					&config,
					std::io::stdin().lock(),
					&mut std::io::stdout().lock(),
				),
				Err(error) => {
					eprintln!("error: {error}");
					ExitCode::FAILURE
				}
			},
			Command::Accounts { config } => match Config::load(&config) {
				Ok(config) => accounts::list(&config, &mut std::io::stdout().lock()),
				Err(error) => {
					eprintln!("error: {error}");
					ExitCode::FAILURE
				}
			},
			Command::AccountAdd {
				config,
				name,
				addresses,
			} => match Config::load(&config) {
				Ok(config) => accounts::add(&config, &name, addresses, std::io::stdin().lock()),
				Err(error) => {
					eprintln!("error: {error}");
					ExitCode::FAILURE
				}
			},
			Command::Queue { config } => match Config::load(&config) {
				Ok(config) => queue::list(&config.data_dir, &mut std::io::stdout().lock()),
				Err(error) => {
					eprintln!("error: {error}");
					ExitCode::FAILURE
				}
			},
			Command::DkimKeygen { out } => dkim_keygen(&out),
			Command::TokenHash => token_hash(),
			Command::AppPasswordCreate {
				config,
				account,
				label,
				expires_at,
				ip_cidr,
			} => match Config::load(&config) {
				Ok(config) => app_passwords::create(
					&config,
					&account,
					&label,
					expires_at,
					ip_cidr,
					&mut std::io::stdout().lock(),
				),
				Err(error) => {
					eprintln!("error: {error}");
					ExitCode::FAILURE
				}
			},
			Command::AppPasswords { config } => match Config::load(&config) {
				Ok(config) => app_passwords::list(&config, &mut std::io::stdout().lock()),
				Err(error) => {
					eprintln!("error: {error}");
					ExitCode::FAILURE
				}
			},
			Command::AppPasswordRevoke {
				config,
				account,
				label,
			} => match Config::load(&config) {
				Ok(config) => {
					app_passwords::revoke(&config, &account, &label, &mut std::io::stdout().lock())
				}
				Err(error) => {
					eprintln!("error: {error}");
					ExitCode::FAILURE
				}
			},
			Command::ApiKeyCreate {
				config,
				label,
				expires_at,
				ip_cidr,
			} => match Config::load(&config) {
				Ok(config) => api_keys::create(
					&config,
					&label,
					expires_at,
					ip_cidr,
					&mut std::io::stdout().lock(),
				),
				Err(error) => {
					eprintln!("error: {error}");
					ExitCode::FAILURE
				}
			},
			Command::ApiKeys { config } => match Config::load(&config) {
				Ok(config) => api_keys::list(&config, &mut std::io::stdout().lock()),
				Err(error) => {
					eprintln!("error: {error}");
					ExitCode::FAILURE
				}
			},
			Command::ApiKeyRevoke { config, label } => match Config::load(&config) {
				Ok(config) => api_keys::revoke(&config, &label, &mut std::io::stdout().lock()),
				Err(error) => {
					eprintln!("error: {error}");
					ExitCode::FAILURE
				}
			},
		}
	}
}

#[cfg(test)]
#[path = "cli_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "cli_tests_b.rs"]
mod tests_b;
