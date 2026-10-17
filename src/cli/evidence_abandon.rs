//! `epistle evidence abandon <spool-id>`: close an acceptance that nothing
//! will ever settle.
//!
//! A submission that is retried leaves behind the acceptance of the attempt
//! that never reached the queue (a stop between the record and the queue, an
//! error that was not clear). It has no outcome and no abandonment, and every
//! bundle of the same message or recipient fails on it. This closes it, with
//! the operator's reason, in the chain.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use serde_json::json;
use uuid::Uuid;

use super::term::sanitize;
use crate::evidence::ack::Operator;
use crate::evidence::chain::Chain;
use crate::evidence::record::{Abandoned, Entry, bounded};

/// What the chain says of one message.
#[derive(Default)]
struct Told {
	accepted: Option<u32>,
	closed: bool,
}

fn told(root: &Path, id: Uuid) -> std::io::Result<Told> {
	let mut told = Told::default();
	let chain = Chain::open(root)?;
	for day in chain.days()? {
		crate::evidence::verify::walk_day(root, day, None, |_, record, _| match &record.entry {
			Entry::Accepted(accepted) if accepted.spool_id == id => {
				told.accepted = Some(accepted.retention.days);
			}
			Entry::Outcome(outcome) if outcome.spool_id == id => told.closed = true,
			Entry::Abandoned(abandoned) if abandoned.spool_id == id => told.closed = true,
			_ => {}
		})
		.map_err(|at| std::io::Error::new(std::io::ErrorKind::InvalidData, at.to_string()))?;
	}
	Ok(told)
}

/// Close the acceptance of `id` under `data_dir`.
pub(super) fn run(
	data_dir: &Path,
	id: Uuid,
	reason: &str,
	yes: bool,
	as_json: bool,
	out: &mut impl Write,
) -> ExitCode {
	let root = crate::evidence::service::root_of(data_dir);
	if !root.is_dir() {
		return super::exit::refused("there is no evidence log yet");
	}
	let reason = reason.trim();
	if reason.is_empty() {
		return super::exit::refused("--reason must say why the acceptance is closed");
	}
	let operator = match Operator::current(&root) {
		Ok(operator) => operator,
		Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
			return super::exit::refused(error);
		}
		Err(error) => {
			super::style::error(format_args!("evidence: {}", error.kind()));
			return ExitCode::FAILURE;
		}
	};
	let told = match told(&root, id) {
		Ok(told) => told,
		Err(error) => {
			super::style::error(format_args!(
				"reading the evidence: {}",
				sanitize(&error.to_string())
			));
			return ExitCode::FAILURE;
		}
	};
	let Some(days) = told.accepted else {
		return super::exit::refused(format_args!(
			"{id}: no acceptance of this message in the log"
		));
	};
	if told.closed {
		return super::exit::refused(format_args!(
			"{id}: it already has an outcome or was abandoned"
		));
	}
	let question = format!(
		"Close the acceptance {id}? It has no outcome and is not in the queue; the record says {} \
		 closed it, and why. [y/N] ",
		sanitize(operator.as_str())
	);
	if let Err(code) = super::prompt::confirm_destructive("closing the acceptance", &question, yes)
	{
		return code;
	}
	let why = format!("closed by {}: {}", clean(operator.as_str()), clean(reason));
	// A message the queue holds is settled by the worker. The check and the
	// record are one step under the spool's lock; anything but a clean "not
	// there" leaves the acceptance as it is.
	let closed = crate::storage::FsSpool::open(data_dir).and_then(|spool| {
		spool.while_absent(id, || {
			Chain::open(&root).and_then(|chain| {
				chain.append(Entry::Abandoned(Abandoned {
					spool_id: id,
					reason: bounded(&why),
					retain_days: days,
				}))
			})
		})
	});
	if let Err(error) = closed {
		return match error.kind() {
			std::io::ErrorKind::AlreadyExists => super::exit::refused(format_args!(
				"{id}: the queue holds it; its outcome will be recorded when it is delivered or given up"
			)),
			_ => {
				super::style::error(format_args!(
					"{id} was not closed: {}",
					sanitize(&error.to_string())
				));
				ExitCode::FAILURE
			}
		};
	}
	if as_json {
		return super::evidence::json(
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
