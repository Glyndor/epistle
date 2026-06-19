//! Command-line interface: argument parsing and command dispatch.

mod accounts;
mod export;
mod import;
mod queue;
mod serve;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use crate::config::Config;

/// Headless mail server: SMTP, IMAP and modern email security through an
/// API and CLI.
#[derive(Debug, Parser)]
#[command(name = "mail", version, disable_help_subcommand = true)]
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
	/// Export an account's mailboxes to an mbox stream on stdout (backup).
	Export {
		/// Path to the configuration file.
		#[arg(long, value_name = "FILE")]
		config: PathBuf,
		/// The account name to export.
		#[arg(long, value_name = "NAME")]
		account: String,
	},
	/// Import an mbox stream from stdin into an account's INBOX (migration).
	Import {
		/// Path to the configuration file.
		#[arg(long, value_name = "FILE")]
		config: PathBuf,
		/// The account name to import into.
		#[arg(long, value_name = "NAME")]
		account: String,
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
			Command::Export { config, account } => match Config::load(&config) {
				Ok(config) => {
					export::run(&config.data_dir, &account, &mut std::io::stdout().lock())
				}
				Err(error) => {
					eprintln!("error: {error}");
					ExitCode::FAILURE
				}
			},
			Command::Import { config, account } => match Config::load(&config) {
				Ok(config) => import::run(&config.data_dir, &account, std::io::stdin().lock()),
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
		}
	}
}

fn token_hash() -> ExitCode {
	token_hash_from(std::io::stdin().lock())
}

/// Read one non-empty line (CR-trimmed) from `reader`, or a FAILURE code.
pub(super) fn read_line(reader: impl std::io::BufRead) -> Result<String, ExitCode> {
	let value = match reader.lines().next() {
		Some(Ok(line)) => line.trim_end_matches('\r').to_owned(),
		Some(Err(error)) => {
			eprintln!("error: reading stdin: {error}");
			return Err(ExitCode::FAILURE);
		}
		None => {
			eprintln!("error: no input — pipe or type the value on stdin");
			return Err(ExitCode::FAILURE);
		}
	};
	if value.is_empty() {
		eprintln!("error: input must not be empty");
		return Err(ExitCode::FAILURE);
	}
	Ok(value)
}

fn token_hash_from(reader: impl std::io::BufRead) -> ExitCode {
	let token = match read_line(reader) {
		Ok(token) => token,
		Err(code) => return code,
	};
	let digest = ring::digest::digest(&ring::digest::SHA256, token.as_bytes());
	let hex = digest
		.as_ref()
		.iter()
		.fold(String::with_capacity(64), |mut s, b| {
			use std::fmt::Write;
			write!(s, "{b:02x}").ok();
			s
		});
	println!("sha256:{hex}");
	ExitCode::SUCCESS
}

fn dkim_keygen(out: &std::path::Path) -> ExitCode {
	if out.exists() {
		eprintln!(
			"error: {} already exists, refusing to overwrite",
			out.display()
		);
		return ExitCode::FAILURE;
	}
	let (pem, record) = match crate::dkim::generate_key() {
		Ok(generated) => generated,
		Err(error) => {
			eprintln!("error: {error}");
			return ExitCode::FAILURE;
		}
	};
	// The private key must never be group/world readable.
	let result = {
		use std::io::Write;
		let mut options = std::fs::OpenOptions::new();
		options.write(true).create_new(true);
		#[cfg(unix)]
		{
			use std::os::unix::fs::OpenOptionsExt;
			options.mode(0o600);
		}
		options
			.open(out)
			.and_then(|mut file| file.write_all(pem.as_bytes()))
	};
	if let Err(error) = result {
		eprintln!("error: cannot write {}: {error}", out.display());
		return ExitCode::FAILURE;
	}
	println!("private key written to {}", out.display());
	println!("publish this TXT record at <selector>._domainkey.<your-domain>:");
	println!("{record}");
	ExitCode::SUCCESS
}

#[cfg(test)]
#[path = "cli_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "cli_tests_b.rs"]
mod tests_b;
