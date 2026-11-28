//! The destinations the outbound queue holds off, as `epistle queue
//! destinations --json` lists them and the queue routes answer.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use super::waiting::{count, json_rows, waiting};
use crate::queue::backoff::{Hold, Holds};
use crate::queue::destination::Destination;
use crate::storage::{Budget, FsSpool};

/// A destination on hold.
pub type Held = (Destination, Hold);

/// The holds in force at `now`, by destination.
pub fn held(spool: &FsSpool, now: u64) -> std::io::Result<Vec<Held>> {
	let holds = Holds::read(spool)?;
	Ok(holds
		.in_force(now)
		.into_iter()
		.map(|(destination, hold)| (destination.clone(), hold.clone()))
		.collect())
}

/// The rows `epistle queue destinations --json` prints: each destination on
/// hold, then each receiver group at its warm-up cap.
pub fn rows(spool: &FsSpool, now: u64) -> std::io::Result<Vec<Value>> {
	let held = held(spool, now)?;
	let capped = waiting(spool)?;
	let mut rows: Vec<Value> = held
		.iter()
		.map(|(destination, hold)| hold_row(destination, hold))
		.collect();
	rows.extend(json_rows(&capped));
	Ok(rows)
}

/// [`rows`] over no more of the queue than `budget` allows, oldest entries
/// first, read once. The flag is true when entries were left unread, so the
/// rows and their counts speak for the part that was read.
pub fn rows_within(
	spool: &FsSpool,
	now: u64,
	mut budget: Budget,
) -> std::io::Result<(Vec<Value>, bool)> {
	let listed = spool.list_after(None, budget.entries())?;
	let mut holds = Holds::default();
	let mut capped = BTreeMap::new();
	let mut ids = listed.ids.into_iter();
	while !budget.is_spent() {
		let Some(id) = ids.next() else { break };
		// An entry that cannot be read is left out, as in [`rows`].
		if let Ok(envelope) = spool.load_envelope_within(id, &mut budget) {
			holds.add_envelope(&envelope);
			count(&mut capped, &envelope);
		}
	}
	let partial = listed.more || ids.next().is_some();
	let mut rows: Vec<Value> = holds
		.in_force(now)
		.into_iter()
		.map(|(destination, hold)| hold_row(destination, hold))
		.collect();
	rows.extend(json_rows(&capped));
	Ok((rows, partial))
}

/// The row of one destination on hold.
fn hold_row(destination: &Destination, hold: &Hold) -> Value {
	json!({
		"kind": destination.kind().label(),
		"name": destination.as_str(),
		"until": hold.until,
		"deferrals": hold.deferrals,
		"reason": hold.reason,
	})
}
