//! The `queue` check: how many messages wait in the outbound spool, how
//! old the oldest is and how many are deferred.

use std::path::Path;

use uuid::Uuid;

use super::Ctx;
use super::clock::epoch;
use super::report::{AreaReport, Item, Level};
use crate::config::Storage;
use crate::storage::FsSpool;

/// The oldest message older than this: warn.
const WARN_AGE_SECS: i64 = 4 * 3600;

/// The oldest message older than this: fail.
const FAIL_AGE_SECS: i64 = 24 * 3600;

/// Check the outbound spool.
pub(super) async fn check(ctx: &Ctx) -> AreaReport {
	let config = match ctx.loaded() {
		Ok(config) => config,
		Err(report) => return report,
	};
	let data_dir = config.data_dir.clone();
	let storage = config.storage.clone();
	let now = epoch(ctx.now);
	tokio::task::spawn_blocking(move || evaluate(&data_dir, storage.as_ref(), now))
		.await
		.unwrap_or_else(|error| AreaReport::fail(format!("spool scan failed: {error}")))
}

/// Read the spool under `data_dir` as of `now` (epoch seconds), with the key
/// `storage` configures so sealed envelopes are read rather than counted as
/// unreadable. Reading never creates the spool directories and never touches
/// message bodies.
fn evaluate(data_dir: &Path, storage: Option<&Storage>, now: i64) -> AreaReport {
	if !data_dir.join("spool").join("new").is_dir() {
		return AreaReport::ok("0 messages queued (no spool yet)");
	}
	let spool = match FsSpool::open_configured(data_dir, storage) {
		Ok(spool) => spool,
		Err(error) => return AreaReport::fail(format!("cannot open the spool: {error}")),
	};
	let ids = match spool.list() {
		Ok(ids) => ids,
		Err(error) => return AreaReport::fail(format!("cannot read the spool: {error}")),
	};
	let mut deferred = 0usize;
	let mut unreadable = 0usize;
	// An operator hold (`epistle queue hold`) is deliberate: held entries are
	// counted on their own and never make the queue look stuck.
	let mut held = 0usize;
	let mut waiting = Vec::with_capacity(ids.len());
	for id in &ids {
		match spool.load_envelope(*id) {
			Ok(envelope) if envelope.held.is_some() => held += 1,
			Ok(envelope) => {
				if envelope.attempts > 0 || envelope.next_attempt as i64 > now {
					deferred += 1;
				}
				waiting.push(*id);
			}
			Err(_) => {
				unreadable += 1;
				waiting.push(*id);
			}
		}
	}
	// Ids are UUID v7, so the first one carries the oldest enqueue time.
	let oldest = waiting.iter().find_map(|id| enqueued_at(*id));
	let held = if held > 0 {
		format!(", {held} held")
	} else {
		String::new()
	};
	let mut items = vec![Item::new(
		"messages",
		Level::Ok,
		format!("{} queued, {deferred} deferred{held}", ids.len()),
	)];
	if unreadable > 0 {
		items.push(Item::new(
			"entries",
			Level::Warn,
			format!("{unreadable} spool entries could not be read"),
		));
	}
	let summary = match oldest {
		Some(at) => {
			let age = (now - at).max(0);
			items.push(age_item(age));
			format!(
				"{} queued, oldest {}, {deferred} deferred{held}",
				ids.len(),
				human(age)
			)
		}
		None => format!("{} queued, {deferred} deferred{held}", ids.len()),
	};
	AreaReport::from_items(items, summary)
}

fn age_item(age: i64) -> Item {
	let level = if age > FAIL_AGE_SECS {
		Level::Fail
	} else if age > WARN_AGE_SECS {
		Level::Warn
	} else {
		Level::Ok
	};
	Item::new(
		"oldest",
		level,
		format!("oldest message is {} old", human(age)),
	)
}

/// Epoch seconds at which a v7 spool id was minted.
fn enqueued_at(id: Uuid) -> Option<i64> {
	let (secs, _) = id.get_timestamp()?.to_unix();
	i64::try_from(secs).ok()
}

fn human(secs: i64) -> String {
	match secs {
		s if s >= 86_400 => format!("{}d{}h", s / 86_400, s % 86_400 / 3600),
		s if s >= 3600 => format!("{}h{}m", s / 3600, s % 3600 / 60),
		s if s >= 60 => format!("{}m", s / 60),
		s => format!("{s}s"),
	}
}

#[cfg(test)]
#[path = "queue_area_tests.rs"]
mod tests;
