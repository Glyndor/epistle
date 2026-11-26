//! The destinations the outbound queue holds off, as `epistle queue
//! destinations --json` lists them and the queue routes answer.

use serde_json::{Value, json};

use super::waiting::{json_rows, waiting};
use crate::queue::backoff::{Hold, Holds};
use crate::queue::destination::Destination;
use crate::storage::FsSpool;

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
		.map(|(destination, hold)| {
			json!({
				"kind": destination.kind().label(),
				"name": destination.as_str(),
				"until": hold.until,
				"deferrals": hold.deferrals,
				"reason": hold.reason,
			})
		})
		.collect();
	rows.extend(json_rows(&capped));
	Ok(rows)
}
