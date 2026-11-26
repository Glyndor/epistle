//! What `epistle queue` shows of the IP warm-up: the recipients waiting
//! for the daily cap of their receiver group. They are not deferred and
//! not held; they go out as the cap allows (see `epistle warmup status`).

use std::collections::BTreeMap;
use std::io::Write;

use crate::cli::term::sanitize;
use crate::storage::FsSpool;

pub(super) use crate::queue::inspect::{Waiting, only_waits, waiting, waits};

/// `queue destinations` lines for the groups at their cap.
pub(super) fn lines(waiting: &BTreeMap<String, Waiting>, now: u64, out: &mut impl Write) {
	for (group, wait) in waiting {
		let _ = writeln!(
			out,
			"warm-up {}\tuntil={} (in {}s)\twaiting={}\treason=warm-up cap",
			sanitize(group),
			crate::clock::rfc3339_or_epoch(wait.until),
			wait.until.saturating_sub(now),
			wait.recipients
		);
	}
}

/// The line `queue list` adds when recipients wait for a cap.
pub(super) fn summary(spool: &FsSpool) -> Option<String> {
	let waiting = waiting(spool).ok()?;
	if waiting.is_empty() {
		return None;
	}
	let total: u64 = waiting.values().map(|wait| wait.recipients).sum();
	let groups: Vec<String> = waiting
		.iter()
		.map(|(group, wait)| format!("{} {}", sanitize(group), wait.recipients))
		.collect();
	Some(format!(
		"{total} recipients waiting for the warm-up cap: {} (see `epistle warmup status`)",
		groups.join(", ")
	))
}

#[cfg(test)]
mod tests;
