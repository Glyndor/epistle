//! Getting every sealed day timestamped, with retries.
//!
//! A checkpoint sealed while timestamping was enabled waits for a token.
//! Each pass asks for at most [`MAX_DAYS_PER_PASS`] of them, oldest first;
//! a day that fails is retried after a backoff that doubles from five
//! minutes up to six hours. The attempts are kept in
//! `<evidence>/timestamp-state.json`, so `epistle status` can show what is
//! waiting and why, and only for days still waiting: the file holds one
//! entry per unstamped day, never a history.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::client::obtain;
use super::settings::Settings;
use crate::evidence::checkpoint::{CHECKPOINT_DIR, files, load};
use crate::evidence::day::Day;
use crate::evidence::record::{bounded, sha256};

/// The most days asked for in one pass.
pub const MAX_DAYS_PER_PASS: usize = 7;
/// The first retry delay, in seconds.
pub const FIRST_RETRY: u64 = 300;
/// The longest retry delay, in seconds.
pub const MAX_RETRY: u64 = 6 * 3600;

const STATE_FILE: &str = "timestamp-state.json";

/// The attempts for one day still waiting for its token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Waiting {
	/// Failed attempts so far.
	pub attempts: u32,
	/// Epoch seconds before which the day is not asked for again.
	pub next_attempt: u64,
	/// The last failure, for the operator.
	pub last_error: String,
}

/// What one pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Pass {
	/// Days that got their token.
	pub stamped: Vec<Day>,
	/// Days that failed this time.
	pub failed: Vec<Day>,
}

/// The delay before the attempt after `attempts` failures.
pub fn backoff(attempts: u32) -> u64 {
	FIRST_RETRY
		.saturating_mul(1 << attempts.saturating_sub(1).min(16))
		.min(MAX_RETRY)
}

/// The days waiting for a token and their attempts.
pub fn waiting(evidence_root: &Path) -> std::io::Result<BTreeMap<String, Waiting>> {
	let Some(bytes) =
		crate::evidence::checkpoint::read_bounded(&evidence_root.join(STATE_FILE), 256 * 1024)?
	else {
		return Ok(BTreeMap::new());
	};
	serde_json::from_slice(&bytes)
		.map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

fn save_waiting(evidence_root: &Path, state: &BTreeMap<String, Waiting>) -> std::io::Result<()> {
	let bytes = serde_json::to_vec_pretty(state).map_err(std::io::Error::other)?;
	crate::storage::write_secret(&evidence_root.join(STATE_FILE), &bytes)
}

/// Sealed days that expect a token and have none, oldest first.
pub fn unstamped(evidence_root: &Path) -> std::io::Result<Vec<Day>> {
	let mut days = Vec::new();
	let entries = match std::fs::read_dir(evidence_root.join(CHECKPOINT_DIR)) {
		Ok(entries) => entries,
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(days),
		Err(error) => return Err(error),
	};
	for entry in entries {
		let name = entry?.file_name();
		let Some(day) = name
			.to_str()
			.and_then(|name| name.strip_suffix(".json"))
			.and_then(Day::parse)
		else {
			continue;
		};
		if files(evidence_root, day).tsr.exists() {
			continue;
		}
		if let Some((checkpoint, _)) = load(evidence_root, day)?
			&& checkpoint.timestamp == "enabled"
		{
			days.push(day);
		}
	}
	days.sort();
	Ok(days)
}

/// Ask for the tokens that are due at `now`.
pub async fn stamp_due(
	evidence_root: &Path,
	settings: &Settings,
	now: u64,
) -> std::io::Result<Pass> {
	let mut pass = Pass::default();
	if !settings.enabled {
		return Ok(pass);
	}
	let pending = unstamped(evidence_root)?;
	let mut state = waiting(evidence_root)?;
	let before = state.clone();
	state.retain(|day, _| Day::parse(day).is_some_and(|day| pending.contains(&day)));
	let due: Vec<Day> = pending
		.into_iter()
		.filter(|day| {
			state
				.get(&day.name())
				.is_none_or(|waiting| waiting.next_attempt <= now)
		})
		.take(MAX_DAYS_PER_PASS)
		.collect();
	for day in due {
		let Some((_, bytes)) = load(evidence_root, day)? else {
			continue;
		};
		match obtain(&settings.authorities, &sha256(&bytes)).await {
			Ok(obtained) => {
				crate::storage::write_secret(&files(evidence_root, day).tsr, &obtained.response)?;
				state.remove(&day.name());
				pass.stamped.push(day);
			}
			Err(error) => {
				let entry = state.entry(day.name()).or_insert(Waiting {
					attempts: 0,
					next_attempt: now,
					last_error: String::new(),
				});
				entry.attempts = entry.attempts.saturating_add(1);
				entry.next_attempt = now.saturating_add(backoff(entry.attempts));
				entry.last_error = bounded(&error);
				pass.failed.push(day);
			}
		}
	}
	if state != before {
		save_waiting(evidence_root, &state)?;
	}
	Ok(pass)
}

#[cfg(test)]
#[path = "stamp_tests.rs"]
mod tests;
