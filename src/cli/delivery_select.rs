//! Which delivery records a command asks for: the filters `delivery list`,
//! `delivery export` share, checked once before the log is read.

use std::process::ExitCode;

use super::ListFilters;
use super::style;
use crate::storage::{DeliveryOutcome, DeliveryRecord};

/// The filters of one command line, parsed.
pub(super) struct Selection {
	recipient: Option<String>,
	account: Option<String>,
	since: Option<u64>,
	until: Option<u64>,
	outcome: Option<DeliveryOutcome>,
}

/// The value of a filter that was given, trimmed. A filter that was given
/// and is empty is a usage error: a script whose variable came out empty
/// must not get everything back.
fn present<'a>(flag: &str, value: &'a Option<String>) -> Result<Option<&'a str>, ExitCode> {
	match value.as_deref().map(str::trim) {
		Some("") => {
			style::error(format_args!("{flag} must not be empty"));
			Err(ExitCode::from(2))
		}
		other => Ok(other),
	}
}

/// A `--since` or `--until` value as an epoch second, or the exit code of
/// the refusal already printed.
fn moment(flag: &str, value: &Option<String>, now: u64) -> Result<Option<u64>, ExitCode> {
	let Some(value) = present(flag, value)? else {
		return Ok(None);
	};
	crate::storage::delivery_log::parse_since(value, now).map_err(|error| {
		style::error(format_args!("{flag} {value:?}: {error}"));
		ExitCode::from(2)
	})
}

impl Selection {
	/// Parse `filters`; `now` anchors a duration such as `24h`. A value that
	/// is not understood is refused with exit code 2 rather than matching
	/// nothing.
	pub(super) fn new(filters: &ListFilters, now: u64) -> Result<Self, ExitCode> {
		let outcome = match present("--outcome", &filters.outcome)? {
			None => None,
			Some(value) => match DeliveryOutcome::parse(value) {
				Some(outcome) => Some(outcome),
				None => {
					style::error(format_args!(
						"unknown status {value:?} for --outcome (or --status); expected one of \
						 delivered, deferred, failed, suppressed, canceled"
					));
					return Err(ExitCode::from(2));
				}
			},
		};
		let since = moment("--since", &filters.since, now)?;
		let until = moment("--until", &filters.until, now)?;
		if since.zip(until).is_some_and(|(since, until)| since > until) {
			style::error("--since is after --until");
			return Err(ExitCode::from(2));
		}
		let recipient = present("--recipient", &filters.recipient)?.map(str::to_string);
		let account = present("--account", &filters.account)?.map(str::to_string);
		Ok(Self {
			recipient,
			account,
			since,
			until,
			outcome,
		})
	}

	/// Whether `record` passes every filter that was given.
	pub(super) fn matches(&self, record: &DeliveryRecord) -> bool {
		self.recipient
			.as_deref()
			.is_none_or(|recipient| record.recipient == recipient)
			&& self
				.account
				.as_deref()
				.is_none_or(|account| record.account.as_deref() == Some(account))
			&& self.since.is_none_or(|since| record.time >= since)
			&& self.until.is_none_or(|until| record.time <= until)
			&& self.outcome.is_none_or(|outcome| record.outcome == outcome)
	}
}
