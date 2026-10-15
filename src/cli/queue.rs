//! `epistle queue`: inspect and steer the outbound delivery spool.
//!
//! The running worker re-reads every envelope from disk on each pass, so the
//! edits made here (retry, hold, release) reach it without a restart. They go
//! through [`FsSpool::update_envelope`], which serializes them against the
//! worker's own writes. No command here ever reads or prints a message body.

use std::io::Write;

use super::term::table::Table;
use std::collections::BTreeMap;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Args, Subcommand};
use serde::Serialize;
use uuid::Uuid;

use crate::config::Storage;
use crate::storage::{DeliveryLog, DeliveryOutcome, DeliveryRecord, Envelope, FsSpool};

#[path = "queue_destinations.rs"]
mod destinations;
#[path = "queue_warmup.rs"]
mod warmup;

/// Operator actions on the outbound queue.
#[derive(Debug, Subcommand)]
pub enum QueueCli {
	/// List queued messages (the default when no action is given).
	List {
		/// Print one JSON array instead of text lines.
		#[arg(long)]
		json: bool,
	},
	/// Show one entry's envelope and retry state; never the message body.
	Show {
		/// Spool id of the entry.
		id: Uuid,
		/// Print one JSON object instead of `key: value` lines.
		#[arg(long)]
		json: bool,
	},
	/// Make the next delivery attempt happen now, skipping the backoff.
	Retry(Target),
	/// Never attempt the entry until it is released.
	Hold(Target),
	/// Release a held entry so it is attempted again.
	Release(Target),
	/// Show the destinations on hold, until when, and why.
	Destinations {
		/// Print one JSON array instead of text lines.
		#[arg(long)]
		json: bool,
	},
	/// Lift the hold on a destination so the queue contacts it again now.
	ReleaseDestination(destinations::DestinationTarget),
	/// Delete one entry from the queue without delivering or bouncing it.
	Remove {
		/// Spool id of the entry.
		id: Uuid,
		/// Skip the interactive confirmation. A non-interactive run
		/// without `--yes` is refused with exit code 2; on a terminal
		/// the operator is asked to type `y`.
		#[arg(long, short = 'y')]
		yes: bool,
	},
}

/// One entry by id, or every entry with `--all`.
#[derive(Debug, Args)]
pub struct Target {
	/// Spool id of the entry.
	#[arg(required_unless_present = "all", conflicts_with = "all")]
	id: Option<Uuid>,
	/// Apply to every entry in the queue.
	#[arg(long)]
	all: bool,
}

/// Run one queue action against the spool under `data_dir`, writing data to
/// `out`. `now` is the current epoch second (injectable for tests).
/// `delivery_log_days` is the operator's configured retention for the
/// per-recipient delivery log; `0` disables the log and the remove action
/// then records nothing. `webhook` is the optional advisory webhook the
/// server is configured with; the `remove` action fires a `Canceled`
/// event for every pending recipient when it is set.
pub(super) fn run(
	data_dir: &Path,
	storage: Option<&Storage>,
	delivery_log_days: u64,
	action: Option<QueueCli>,
	now: u64,
	webhook: Option<&Arc<crate::webhook::Webhook>>,
	out: &mut impl Write,
) -> ExitCode {
	let action = action.unwrap_or(QueueCli::List { json: false });
	let spool = match FsSpool::open_configured(data_dir, storage) {
		Ok(spool) => spool,
		Err(error) => return fail(format_args!("opening spool: {error}")),
	};
	let log = DeliveryLog::open(data_dir, delivery_log_days);
	match action {
		QueueCli::List { json: false } => list(data_dir, storage, out),
		QueueCli::List { json: true } => list_json(&spool, out),
		QueueCli::Show { id, json: false } => show(&spool, id, now, out),
		QueueCli::Show { id, json: true } => show_json(&spool, id, out),
		QueueCli::Retry(target) => edit_many(&spool, &target, "retried", out, |e| {
			e.next_attempt = 0;
		}),
		QueueCli::Hold(target) => edit_many(&spool, &target, "held", out, |e| e.hold(now)),
		QueueCli::Release(target) => edit_many(&spool, &target, "released", out, |e| {
			e.release(now);
		}),
		QueueCli::Destinations { json } => destinations::list(&spool, now, json, out),
		QueueCli::ReleaseDestination(target) => destinations::release(&spool, &target, now, out),
		QueueCli::Remove { id, yes } => {
			let envelope = match spool.load_envelope(id) {
				Ok(envelope) => envelope,
				Err(error) => return entry_error(id, &error),
			};
			let sender = if envelope.reverse_path.is_empty() {
				"<>"
			} else {
				envelope.reverse_path.as_str()
			};
			let question = format!(
				"Remove queued message {id} from {sender} to {} recipients? \
				 It will not be delivered and no bounce is sent. [y/N]",
				envelope.recipients.len()
			);
			if let Err(code) = super::prompt::confirm_destructive("queue remove", &question, yes) {
				return code;
			}
			match spool.remove(id) {
				Ok(()) => {
					// Record the cancel for every recipient that was still
					// pending. Already-delivered recipients are not touched
					// (their `delivered` record is the only thing the log
					// needs to know about); a recipient that was already
					// failed is past the cancel and the spool removal is a
					// no-op for them.
					if log.is_enabled() {
						for recipient in &envelope.recipients {
							let state = envelope.recipient_state(recipient);
							if state.status == crate::storage::RecipientStatus::Pending {
								let record = DeliveryRecord {
									time: now,
									spool_id: id,
									account: envelope.account.clone(),
									from: envelope.reverse_path.clone(),
									recipient: recipient.clone(),
									outcome: DeliveryOutcome::Canceled,
									remote: state.remote.clone(),
									reply: state.last_error.clone(),
									attempt: state.attempts,
									extra: BTreeMap::new(),
								};
								if let Err(error) = log.append(&record) {
									tracing::warn!(%id, %error, "delivery log write failed");
								}
								if let Some(webhook) = webhook {
									let webhook = webhook.clone();
									let event = crate::webhook::WebhookEvent::Canceled {
										spool_id: id,
										recipient: recipient.clone(),
										extra: BTreeMap::new(),
									};
									tokio::spawn(async move { webhook.notify(&event).await });
								}
							}
						}
					}
					let _ = writeln!(out, "removed {id}");
					ExitCode::SUCCESS
				}
				Err(error) => entry_error(id, &error),
			}
		}
	}
}

/// The current epoch second.
pub(super) fn now_epoch() -> u64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0)
}

fn fail(message: impl std::fmt::Display) -> ExitCode {
	super::style::error(message);
	ExitCode::FAILURE
}

fn entry_error(id: Uuid, error: &std::io::Error) -> ExitCode {
	if error.kind() == std::io::ErrorKind::NotFound {
		super::exit::refused(format_args!("no such queue entry: {id}"))
	} else {
		fail(format_args!("queue entry {id}: {error}"))
	}
}

/// List the outbound spool: one line per message with its envelope and retry
/// state. Writes to `out` so the formatting is unit-testable.
pub(super) fn list(data_dir: &Path, storage: Option<&Storage>, out: &mut impl Write) -> ExitCode {
	let spool = match FsSpool::open_configured(data_dir, storage) {
		Ok(spool) => spool,
		Err(error) => return fail(format_args!("opening spool: {error}")),
	};
	let ids = match spool.list() {
		Ok(ids) => ids,
		Err(error) => return fail(format_args!("reading spool: {error}")),
	};
	if let Some(decor) = super::term::stdout(false) {
		let mut table = Table::new(&["ID", "STATE", "ATTEMPTS", "FROM", "TO"]).state_col(1);
		for id in &ids {
			let Ok(envelope) = spool.load_envelope(*id) else {
				continue;
			};
			let state = match (envelope.held.is_some(), envelope.attempts) {
				(true, _) => "held",
				(false, _) if warmup::only_waits(&envelope) => "warm-up cap",
				(false, 0) => "queued",
				(false, _) => "deferred",
			};
			table.push(vec![
				id.to_string(),
				state.into(),
				envelope.attempts.to_string(),
				sender(&envelope).to_string(),
				envelope.recipients.join(","),
			]);
		}
		let _ = table.write(decor, out);
		let _ = writeln!(out, "{} queued", ids.len());
		held_destinations(&spool, out);
		return ExitCode::SUCCESS;
	}
	for id in &ids {
		let Ok(envelope) = spool.load_envelope(*id) else {
			continue;
		};
		let held = if envelope.held.is_some() {
			"\theld"
		} else if warmup::waits(&envelope) {
			"\twarm-up cap"
		} else {
			""
		};
		let _ = writeln!(
			out,
			"{id}\tattempts={}\tfrom={}\tto={}{held}",
			envelope.attempts,
			sender(&envelope),
			envelope.recipients.join(",")
		);
	}
	let _ = writeln!(out, "{} queued", ids.len());
	held_destinations(&spool, out);
	ExitCode::SUCCESS
}

/// Say which destinations are on hold, when any is: their messages wait
/// for the hold to end, not for their own retry.
fn held_destinations(spool: &FsSpool, out: &mut impl Write) {
	if let Some(line) = destinations::summary(spool, now_epoch()) {
		let _ = writeln!(out, "{line}");
	}
	if let Some(line) = warmup::summary(spool) {
		let _ = writeln!(out, "{line}");
	}
}

fn sender(envelope: &Envelope) -> &str {
	if envelope.reverse_path.is_empty() {
		"<>"
	} else {
		&envelope.reverse_path
	}
}

/// One entry as printed by `queue list --json`: the envelope only.
#[derive(Serialize)]
struct Row<'a> {
	id: Uuid,
	reverse_path: &'a str,
	recipients: &'a [String],
	attempts: u32,
	next_attempt: u64,
	held: bool,
	/// A pending recipient waits for the warm-up cap of its group.
	warmup_cap: bool,
	last_error: Option<&'a str>,
}

fn list_json(spool: &FsSpool, out: &mut impl Write) -> ExitCode {
	let ids = match spool.list() {
		Ok(ids) => ids,
		Err(error) => return fail(format_args!("reading spool: {error}")),
	};
	let envelopes: Vec<Envelope> = ids
		.iter()
		.filter_map(|id| spool.load_envelope(*id).ok())
		.collect();
	let rows: Vec<Row> = envelopes
		.iter()
		.map(|e| Row {
			id: e.id,
			reverse_path: &e.reverse_path,
			recipients: &e.recipients,
			attempts: e.attempts,
			next_attempt: e.next_attempt,
			held: e.held.is_some(),
			warmup_cap: warmup::waits(e),
			last_error: e.last_error.as_deref(),
		})
		.collect();
	match serde_json::to_writer_pretty(&mut *out, &rows) {
		Ok(()) => {
			let _ = writeln!(out);
			ExitCode::SUCCESS
		}
		Err(error) => fail(format_args!("writing JSON: {error}")),
	}
}

fn show(spool: &FsSpool, id: Uuid, now: u64, out: &mut impl Write) -> ExitCode {
	let envelope = match spool.load_envelope(id) {
		Ok(envelope) => envelope,
		Err(error) => return entry_error(id, &error),
	};
	let _ = writeln!(out, "id: {id}");
	let _ = writeln!(out, "from: {}", sender(&envelope));
	let _ = writeln!(out, "to: {}", envelope.recipients.join(", "));
	let _ = writeln!(out, "attempts: {}", envelope.attempts);
	let next = if envelope.next_attempt <= now {
		"now".to_string()
	} else {
		format!(
			"{} (in {}s)",
			envelope.next_attempt,
			envelope.next_attempt - now
		)
	};
	let _ = writeln!(out, "next attempt: {next}");
	match envelope.held {
		Some(since) => {
			let _ = writeln!(out, "held: yes, since {since}");
		}
		None => {
			let _ = writeln!(out, "held: no");
		}
	}
	let _ = writeln!(out, "require tls: {}", envelope.require_tls);
	// The last error is a remote server's reply: shown with its control
	// characters escaped.
	let _ = writeln!(
		out,
		"last error: {}",
		super::term::sanitize(envelope.last_error.as_deref().unwrap_or("none"))
	);
	ExitCode::SUCCESS
}

/// `queue show --json`: the envelope fields of `queue list --json`, plus
/// when the hold started and whether TLS is required.
fn show_json(spool: &FsSpool, id: Uuid, out: &mut impl Write) -> ExitCode {
	let envelope = match spool.load_envelope(id) {
		Ok(envelope) => envelope,
		Err(error) => return entry_error(id, &error),
	};
	let view = serde_json::json!({
		"id": envelope.id,
		"reverse_path": envelope.reverse_path,
		"recipients": envelope.recipients,
		"attempts": envelope.attempts,
		"next_attempt": envelope.next_attempt,
		"held": envelope.held.is_some(),
		"held_since": envelope.held,
		"require_tls": envelope.require_tls,
		"last_error": envelope.last_error,
	});
	super::json_out::print(out, &view)
}

/// Apply `edit` to one entry or to every entry, then say how many changed.
fn edit_many(
	spool: &FsSpool,
	target: &Target,
	verb: &str,
	out: &mut impl Write,
	edit: impl Fn(&mut Envelope),
) -> ExitCode {
	if let Some(id) = target.id {
		return match spool.update_envelope(id, edit) {
			Ok(envelope) => {
				let _ = writeln!(out, "{verb} {id}");
				note_if_held(verb, &envelope, out);
				ExitCode::SUCCESS
			}
			Err(error) => entry_error(id, &error),
		};
	}
	let ids = match spool.list() {
		Ok(ids) => ids,
		Err(error) => return fail(format_args!("reading spool: {error}")),
	};
	let mut changed = 0usize;
	for id in ids {
		match spool.update_envelope(id, &edit) {
			Ok(_) => changed += 1,
			// The worker delivered or dropped it since the listing.
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
			Err(error) => return entry_error(id, &error),
		}
	}
	let _ = writeln!(out, "{verb} {changed} entries");
	ExitCode::SUCCESS
}

/// A retry does not lift a hold; tell the operator so they are not surprised.
fn note_if_held(verb: &str, envelope: &Envelope, out: &mut impl Write) {
	if verb == "retried" && envelope.held.is_some() {
		let _ = writeln!(out, "note: the entry is held, release it to send it");
	}
}

#[cfg(test)]
#[path = "queue_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "queue_tests_destinations.rs"]
mod tests_destinations;
