//! `epistle evidence`: verify, export and check the evidence of sending,
//! set what is kept and for how long, and manage timestamping.
//!
//! Every action but `check` reads the server's data directory and runs as
//! the service account. `check` reads nothing but the bundle it is given:
//! it is what a third party runs, without any server.

mod abandon;
mod bundle;
mod clock;
mod key;
mod policy;
mod timestamp;
mod verify;

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
		/// Succeed even when some of the records are of a day that is not
		/// sealed yet, and so are left out of the bundle.
		#[arg(long)]
		allow_unsealed: bool,
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
		/// Require the bundle to cover the days from this one (`YYYY-MM-DD`).
		#[arg(long, value_parser = parse_day)]
		from: Option<Day>,
		/// Require the bundle to cover the days up to this one (`YYYY-MM-DD`).
		#[arg(long, value_parser = parse_day)]
		to: Option<Day>,
		/// Also trust this timestamp key: hex SHA-256 of its
		/// SubjectPublicKeyInfo. The default authority's is always trusted.
		#[arg(long = "anchor", value_name = "SHA256")]
		anchors: Vec<String>,
		/// Exit with 1 unless every recipient the bundle covers was delivered.
		/// Without it a bundle that proves a message bounced, expired or
		/// was never sent verifies, and says so.
		#[arg(long)]
		require_delivered: bool,
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
	/// Tell the server the machine's clock is right.
	///
	/// A server stopped for more than a day, or that could not read its log,
	/// seals, purges and expires nothing until a timestamp authority or you
	/// vouch for the clock.
	Clock {
		/// Clock action (`accept`).
		#[command(subcommand)]
		action: ClockCli,
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
	/// Close an acceptance that nothing will settle.
	///
	/// A retried submission can leave the acceptance of the attempt that never
	/// reached the queue, with no outcome. Every bundle of the same message
	/// fails on it until it is closed. The record names the operator and the
	/// reason; only an acceptance that has no outcome and is not in the queue
	/// can be closed.
	Abandon {
		/// The queue id of the acceptance (`evidence verify` and the bundle's
		/// error name it).
		spool_id: uuid::Uuid,
		/// Why it is closed (kept in the evidence).
		#[arg(long)]
		reason: String,
		/// Do not ask; required when there is no terminal.
		#[arg(long)]
		yes: bool,
		/// Print one JSON object instead of text.
		#[arg(long)]
		json: bool,
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

/// Clock actions.
#[derive(Debug, Subcommand)]
pub enum ClockCli {
	/// Take the clock this machine reads now as the real date.
	Accept {
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
		from,
		to,
		anchors,
		require_delivered,
		json,
	} = action
	{
		let expected = crate::evidence::bundle::Expectation {
			message_id,
			recipient,
			from,
			to,
		};
		return bundle::check(
			&bundle,
			&keys,
			&expected,
			(&anchors, require_delivered),
			json,
			out,
		);
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
		EvidenceCli::Verify { from, to, json } => verify::verify(&root, from, to, now, json, out),
		EvidenceCli::Export {
			message_id,
			recipient,
			from,
			to,
			out: bundle,
			allow_unsealed,
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
			bundle::export(
				&root,
				&crypto,
				&selector,
				&bundle,
				(json, allow_unsealed),
				out,
			)
		}
		EvidenceCli::Key { action } => key::run(&root, action, now, out),
		EvidenceCli::Clock { action } => clock::run(&root, action, now, out),
		EvidenceCli::Policy { action } => policy::run(&root, action, out),
		EvidenceCli::Timestamp { action } => timestamp::run(&root, action, out),
		EvidenceCli::Abandon {
			spool_id,
			reason,
			yes,
			json,
		} => abandon::run(&config.data_dir, (spool_id, &reason), (yes, json, now), out),
		EvidenceCli::Acknowledge { reason, yes, json } => {
			verify::acknowledge(&root, &reason, yes, now, json, out)
		}
	}
}

/// Write `value` as one line of JSON.
pub(super) fn json(out: &mut impl Write, value: &serde_json::Value) -> ExitCode {
	super::json_out::print(out, value)
}

#[cfg(test)]
mod tests;
