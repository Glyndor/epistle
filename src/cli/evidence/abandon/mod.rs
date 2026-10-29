//! `epistle evidence abandon <spool-id>`: close an acceptance that nothing
//! will ever settle.
//!
//! A submission that is retried leaves behind the acceptance of the attempt
//! that never reached the queue (a stop between the record and the queue, an
//! error that was not clear), or the recipients of a message that were left
//! without an outcome while the others were settled. They have no outcome and
//! no abandonment, and every bundle of the same message or recipient fails on
//! them. This closes them, with the operator and the reason, in the chain.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use serde_json::json;
use uuid::Uuid;

use crate::cli::term::sanitize;
use crate::evidence::ack::Operator;
use crate::evidence::chain::Chain;
use crate::evidence::record::{Abandoned, Entry, bounded};

/// The youngest an acceptance can be to be closed: a submission writes its
/// acceptance before the entry is in the queue, and a message still on its way
/// there is not an orphan.
const MIN_AGE_SECS: u64 = 600;

/// What the chain says of one message.
#[derive(Default)]
struct Told {
	/// Retention days, the time and the recipients of its acceptance.
	accepted: Option<(u32, u64, Vec<String>)>,
	/// Recipients with an outcome or closed one by one (lowercase).
	ended: Vec<String>,
	/// The whole message was abandoned.
	abandoned: bool,
}

impl Told {
	/// The recipients nothing has ended.
	fn pending(&self) -> Vec<String> {
		let Some((_, _, recipients)) = &self.accepted else {
			return Vec::new();
		};
		match self.abandoned {
			true => Vec::new(),
			false => recipients
				.iter()
				.filter(|recipient| !self.ended.contains(&recipient.to_ascii_lowercase()))
				.cloned()
				.collect(),
		}
	}
}

fn told(root: &Path, id: Uuid) -> std::io::Result<Told> {
	let mut told = Told::default();
	let chain = Chain::open(root)?;
	for day in chain.days()? {
		// Past the breaks an operator acknowledged, as the verification is: a
		// break nobody did is an error and nothing is closed on it. A day is
		// read again after each break gone past, so this only ever sets.
		crate::evidence::ack::walk_day_acknowledged(root, day, |_, record, _| {
			match &record.entry {
				Entry::Accepted(accepted) if accepted.spool_id == id => {
					told.accepted = Some((
						accepted.retention.days,
						record.time,
						accepted.recipients.clone(),
					));
				}
				Entry::Outcome(outcome) if outcome.spool_id == id => {
					let recipient = outcome.recipient.to_ascii_lowercase();
					if !told.ended.contains(&recipient) {
						told.ended.push(recipient);
					}
				}
				Entry::Abandoned(abandoned) if abandoned.spool_id == id => {
					match abandoned.recipients.is_empty() {
						true => told.abandoned = true,
						false => {
							for recipient in &abandoned.recipients {
								let recipient = recipient.to_ascii_lowercase();
								if !told.ended.contains(&recipient) {
									told.ended.push(recipient);
								}
							}
						}
					}
				}
				_ => {}
			}
		})
		.map_err(|at| std::io::Error::new(std::io::ErrorKind::InvalidData, at.to_string()))?;
	}
	Ok(told)
}

/// Why a message is left as it is.
enum Refusal {
	NoAcceptance,
	NothingPending,
	TooRecent,
}

impl Refusal {
	fn say(&self, id: Uuid) -> String {
		match self {
			Self::NoAcceptance => format!("{id}: no acceptance of this message in the log"),
			Self::NothingPending => {
				format!("{id}: every recipient already has an outcome or was closed")
			}
			Self::TooRecent => format!(
				"{id}: accepted less than {} minutes ago; it may still be on its way to the queue",
				MIN_AGE_SECS / 60
			),
		}
	}
}

/// What to close for `id` on what the chain says now: the recipients that
/// have no ending (none named when it is all of them), or why not.
fn to_close(told: &Told, now: u64) -> Result<(u32, Vec<String>), Refusal> {
	let Some((days, time, recipients)) = &told.accepted else {
		return Err(Refusal::NoAcceptance);
	};
	let pending = told.pending();
	if pending.is_empty() {
		return Err(Refusal::NothingPending);
	}
	if now.saturating_sub(*time) < MIN_AGE_SECS {
		return Err(Refusal::TooRecent);
	}
	let all = pending.len() == recipients.len();
	Ok((*days, if all { Vec::new() } else { pending }))
}

/// Write the closing of `id`, if there is still something to close. A message
/// the queue holds is settled by the worker. What the chain says is read
/// again, and the record written, under the spool's lock and with the queue
/// seen empty: a worker that delivered meanwhile wrote its outcome before it
/// let go of the entry, so it is seen here. Anything but a clean "not there"
/// leaves the acceptance as it is.
fn close(
	data_dir: &Path,
	(root, id): (&Path, Uuid),
	why: &str,
	now: u64,
) -> std::io::Result<Result<(), Refusal>> {
	crate::storage::FsSpool::open(data_dir).and_then(|spool| {
		spool.while_absent(id, || {
			let fresh = told(root, id)?;
			let (days, recipients) = match to_close(&fresh, now) {
				Ok(close) => close,
				Err(refusal) => return Ok(Err(refusal)),
			};
			Chain::open(root)?.append(Entry::Abandoned(Abandoned {
				spool_id: id,
				reason: bounded(why),
				retain_days: days,
				recipients,
			}))?;
			Ok(Ok(()))
		})
	})
}

/// Close the acceptance of `id` under `data_dir`.
pub(super) fn run(
	data_dir: &Path,
	(id, reason): (Uuid, &str),
	(yes, as_json, now): (bool, bool, u64),
	out: &mut impl Write,
) -> ExitCode {
	let root = crate::evidence::service::root_of(data_dir);
	if !root.is_dir() {
		return crate::cli::exit::refused("there is no evidence log yet");
	}
	let reason = clean(reason);
	if reason.trim().is_empty() {
		return crate::cli::exit::refused("--reason must say why the acceptance is closed");
	}
	let operator = match Operator::current(&root) {
		Ok(operator) => operator,
		Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
			return crate::cli::exit::refused(error);
		}
		Err(error) => {
			crate::cli::style::error(format_args!("evidence: {}", error.kind()));
			return ExitCode::FAILURE;
		}
	};
	let seen = match told(&root, id) {
		Ok(told) => told,
		Err(error) => {
			crate::cli::style::error(format_args!(
				"reading the evidence: {}",
				sanitize(&error.to_string())
			));
			return ExitCode::FAILURE;
		}
	};
	if let Err(refusal) = to_close(&seen, now) {
		return crate::cli::exit::refused(refusal.say(id));
	}
	let question = format!(
		"Close the acceptance {id} for {}? It has no outcome and is not in the queue; the record \
		 says {} closed it, and why. [y/N] ",
		sanitize(&seen.pending().join(", ")),
		sanitize(operator.as_str())
	);
	if let Err(code) =
		crate::cli::prompt::confirm_destructive("closing the acceptance", &question, yes)
	{
		return code;
	}
	let why = format!("closed by {}: {reason}", clean(operator.as_str()));
	let closed = close(data_dir, (&root, id), &why, now);
	match closed {
		Ok(Ok(())) => {}
		Ok(Err(refusal)) => return crate::cli::exit::refused(refusal.say(id)),
		Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
			return crate::cli::exit::refused(format_args!(
				"{id}: the queue holds it; its outcome will be recorded when it is delivered or given up"
			));
		}
		Err(error) => {
			crate::cli::style::error(format_args!(
				"{id} was not closed: {}",
				sanitize(&error.to_string())
			));
			return ExitCode::FAILURE;
		}
	}
	if as_json {
		return super::json(
			out,
			&json!({ "closed": id.to_string(), "operator": operator.as_str() }),
		);
	}
	let _ = writeln!(out, "closed {id}: nothing more is expected of it");
	ExitCode::SUCCESS
}

/// `text` as the log keeps it: without control characters or the ones that
/// reorder or hide text, and not long.
fn clean(text: &str) -> String {
	text.chars()
		.filter(|c| !c.is_control() && !crate::evidence::hidden::is_hidden(*c))
		.take(256)
		.collect()
}

#[cfg(test)]
mod tests;
