//! `epistle evidence`: verify, export and check the evidence of sending,
//! set what is kept and for how long, and manage timestamping.
//!
//! Every action but `check` reads the server's data directory and runs as
//! the service account. `check` reads nothing but the bundle it is given:
//! it is what a third party runs, without any server.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Subcommand;

use crate::config::Config;
use crate::evidence::day::Day;
use crate::evidence::policy::Mode;

/// Evidence actions.
#[derive(Debug, Subcommand)]
pub enum EvidenceCli {
	/// Verify the evidence log from its oldest kept day.
	///
	/// This is what the server does every five minutes. Exit code 1 when the
	/// evidence does not verify.
	Verify {
		/// First day to verify (`YYYY-MM-DD`).
		#[arg(long, value_parser = parse_day)]
		from: Option<Day>,
		/// Last day to verify (`YYYY-MM-DD`).
		#[arg(long, value_parser = parse_day)]
		to: Option<Day>,
		/// Print one JSON object instead of text.
		#[arg(long)]
		json: bool,
	},
	/// Export the evidence of a message or a recipient as a bundle.
	///
	/// Anyone can check the bundle without the server.
	Export {
		/// The message's `Message-ID`, exactly as sent (with the brackets).
		#[arg(
			long,
			required_unless_present = "recipient",
			conflicts_with = "recipient"
		)]
		message_id: Option<String>,
		/// A recipient address; needs `--from` and `--to`.
		#[arg(long, requires_all = ["from", "to"])]
		recipient: Option<String>,
		/// First day of acceptance (`YYYY-MM-DD`), with `--recipient`.
		#[arg(long, value_parser = parse_day)]
		from: Option<Day>,
		/// Last day of acceptance (`YYYY-MM-DD`), with `--recipient`.
		#[arg(long, value_parser = parse_day)]
		to: Option<Day>,
		/// The bundle directory to create; it must not exist.
		#[arg(long)]
		out: PathBuf,
		/// Print one JSON object instead of text.
		#[arg(long)]
		json: bool,
	},
	/// Check a bundle offline, against a key you anchor.
	///
	/// No configuration and no server data are read. Exit code 1 when any
	/// check fails.
	Check {
		/// The bundle directory.
		bundle: PathBuf,
		/// The evidence key the operator published: its id (hex SHA-256 of
		/// the public key) or a file holding the public key as PEM. The
		/// current key goes bare; each earlier one needs the day its period
		/// ended, `KEY@YYYY-MM-DD`. Repeatable. Required: a bundle cannot
		/// vouch for the key that signed it, and a key that handed over must
		/// not seal a later day.
		#[arg(long = "key", value_name = "FINGERPRINT|FILE")]
		keys: Vec<String>,
		/// Require the bundle to be about this `Message-ID`, exactly as
		/// sent (with the brackets). A bundle's own manifest is not signed,
		/// so say what the story is about.
		#[arg(long)]
		message_id: Option<String>,
		/// Require the bundle to cover this recipient.
		#[arg(long)]
		recipient: Option<String>,
		/// Also trust this timestamp key: hex SHA-256 of its
		/// SubjectPublicKeyInfo. The default authority's is always trusted.
		#[arg(long = "anchor", value_name = "SHA256")]
		anchors: Vec<String>,
		/// Print one JSON object instead of text.
		#[arg(long)]
		json: bool,
	},
	/// The key that signs the daily seals: show it, or rotate it.
	Key {
		/// Key action (`show`, `rotate`).
		#[command(subcommand)]
		action: KeyCli,
	},
	/// Show or set what evidence is kept, and for how long.
	Policy {
		/// Policy action (`show`, `set`).
		#[command(subcommand)]
		action: PolicyCli,
	},
	/// Timestamping of the daily checkpoints (on by default).
	Timestamp {
		/// Timestamp action (`show`, `enable`, `disable`).
		#[command(subcommand)]
		action: TimestampCli,
	},
	/// Accept the first break in the evidence and take transactional mail again.
	///
	/// The acknowledgement is signed and kept in the chain; the break stays
	/// visible.
	Acknowledge {
		/// Why the break is accepted (kept in the evidence).
		#[arg(long)]
		reason: String,
		/// Do not ask; required when there is no terminal.
		#[arg(long)]
		yes: bool,
		/// Print one JSON object instead of text.
		#[arg(long)]
		json: bool,
	},
}

/// Key actions.
#[derive(Debug, Subcommand)]
pub enum KeyCli {
	/// Show the key's fingerprint, its public half and its predecessors.
	Show {
		/// Print one JSON object instead of text.
		#[arg(long)]
		json: bool,
	},
	/// Make a new key take over from the current one.
	///
	/// The old key signs the hand-over, which is recorded in the evidence.
	Rotate {
		/// Do not ask; required when there is no terminal.
		#[arg(long)]
		yes: bool,
		/// Print one JSON object instead of text.
		#[arg(long)]
		json: bool,
	},
}

/// Policy actions.
#[derive(Debug, Subcommand)]
pub enum PolicyCli {
	/// Show the rules and what each class keeps by default.
	Show {
		/// Print one JSON object instead of text.
		#[arg(long)]
		json: bool,
	},
	/// Set the rule for one class (or `all`) on the server, tenant or account.
	///
	/// Transactional mail always keeps evidence.
	Set {
		/// `transactional`, `marketing`, `personal` or `all`.
		#[arg(long)]
		class: String,
		/// Apply to this account only.
		#[arg(long, conflicts_with = "tenant")]
		account: Option<String>,
		/// Apply to the accounts of this tenant.
		#[arg(long)]
		tenant: Option<String>,
		/// `off`, `metadata` (records and a hash) or `full` (also the message).
		#[arg(long, value_parser = parse_mode)]
		mode: Mode,
		/// Days to keep it.
		#[arg(long, default_value_t = crate::evidence::policy::DEFAULT_DAYS)]
		days: u32,
		/// Print one JSON object instead of text.
		#[arg(long)]
		json: bool,
	},
}

/// Timestamp actions.
#[derive(Debug, Subcommand)]
pub enum TimestampCli {
	/// Show whether timestamping is on, and the authorities.
	Show {
		/// Print one JSON object instead of text.
		#[arg(long)]
		json: bool,
	},
	/// Turn timestamping on. Without `--tsa`, the default authority.
	Enable {
		/// An RFC 3161 authority URL (HTTPS); repeat for fallbacks.
		#[arg(long = "tsa", value_name = "URL", requires = "anchors")]
		urls: Vec<String>,
		/// Hex SHA-256 of a SubjectPublicKeyInfo the authorities' tokens must
		/// chain to; repeatable.
		#[arg(long = "anchor", value_name = "SHA256")]
		anchors: Vec<String>,
		/// A policy OID (`1.2.3.4`) the tokens must carry.
		#[arg(long)]
		policy: Option<String>,
		/// A file (0600, owned by the service account) with a bearer token
		/// for authorities that require one.
		#[arg(long)]
		token_file: Option<PathBuf>,
		/// Print one JSON object instead of text.
		#[arg(long)]
		json: bool,
	},
	/// Turn timestamping off, recorded in the evidence.
	///
	/// Days sealed from then on rest on the evidence key alone.
	Disable {
		/// Do not ask; required when there is no terminal.
		#[arg(long)]
		yes: bool,
		/// Print one JSON object instead of text.
		#[arg(long)]
		json: bool,
	},
}

fn parse_day(value: &str) -> Result<Day, String> {
	Day::parse(value).ok_or_else(|| format!("{value:?} is not a day; use YYYY-MM-DD"))
}

fn parse_mode(value: &str) -> Result<Mode, String> {
	match value {
		"off" => Ok(Mode::Off),
		"metadata" => Ok(Mode::Metadata),
		"full" => Ok(Mode::Full),
		_ => Err(format!(
			"{value:?} is not a mode; use off, metadata or full"
		)),
	}
}

/// Run one evidence action.
pub(super) fn run(
	config_path: &Path,
	action: EvidenceCli,
	now: u64,
	out: &mut impl Write,
) -> ExitCode {
	if let EvidenceCli::Check {
		bundle,
		keys,
		message_id,
		recipient,
		anchors,
		json,
	} = action
	{
		let expected = crate::evidence::bundle::Expectation {
			message_id,
			recipient,
		};
		return super::evidence_bundle::check(&bundle, &keys, &expected, &anchors, json, out);
	}
	let config = match Config::load(config_path) {
		Ok(config) => config,
		Err(error) => {
			super::style::error(error);
			return ExitCode::FAILURE;
		}
	};
	let root = crate::evidence::service::root_of(&config.data_dir);
	match action {
		// Answered above, before any configuration is read.
		EvidenceCli::Check { .. } => ExitCode::FAILURE,
		EvidenceCli::Verify { from, to, json } => {
			super::evidence_verify::verify(&root, from, to, now, json, out)
		}
		EvidenceCli::Export {
			message_id,
			recipient,
			from,
			to,
			out: bundle,
			json,
		} => {
			let crypto = match super::util::message_crypto(&config) {
				Ok(crypto) => crypto,
				Err(code) => return code,
			};
			let selector = match (message_id, recipient, from, to) {
				(Some(id), _, _, _) => crate::evidence::bundle::Selector::MessageId(id),
				(None, Some(address), Some(from), Some(to)) => {
					crate::evidence::bundle::Selector::Recipient { address, from, to }
				}
				_ => {
					return super::exit::refused(
						"give --message-id, or --recipient with --from and --to",
					);
				}
			};
			super::evidence_bundle::export(&root, &crypto, &selector, &bundle, json, out)
		}
		EvidenceCli::Key { action } => super::evidence_key::run(&root, action, now, out),
		EvidenceCli::Policy { action } => super::evidence_policy::run(&root, action, out),
		EvidenceCli::Timestamp { action } => super::evidence_timestamp::run(&root, action, out),
		EvidenceCli::Acknowledge { reason, yes, json } => {
			super::evidence_verify::acknowledge(&root, &reason, yes, now, json, out)
		}
	}
}

/// Write `value` as one line of JSON.
pub(super) fn json(out: &mut impl Write, value: &serde_json::Value) -> ExitCode {
	super::json_out::print(out, value)
}

#[cfg(test)]
#[path = "evidence_tests.rs"]
mod tests;
#[cfg(test)]
#[path = "evidence_tests_key.rs"]
mod tests_key;
