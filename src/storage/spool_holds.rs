//! Destinations the outbound queue is holding off, kept next to the spool.
//!
//! When a recipient domain asks the queue to slow down (a 421, a 4.7.x
//! reply, a rate-limit 451 or 452), the queue stops contacting it until the
//! hold ends. Holds are written to `<data_dir>/spool/destinations.json`, so
//! they survive a restart: a server restarted in the middle of a backoff
//! does not go straight back to the destination that asked it to wait. The
//! file is small (one record per held domain, at most
//! [`crate::queue::backoff::MAX_HOLDS`] of them), rewritten whole under the
//! spool lock and renamed into place, so the operator CLI (`epistle queue
//! destinations`, `epistle queue release-destination`) and the worker never
//! lose each other's edits. The worker reads it from disk each time it
//! decides, never from memory, so a release takes effect at once.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::spool::{FsSpool, write_sync};

/// File name of the holds, under the spool root.
const HOLDS_FILE: &str = "destinations.json";

/// One destination the queue is holding off.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DestinationHold {
	/// Epoch seconds until which the destination is not contacted.
	pub until: u64,
	/// How many times in a row the destination deferred: picks the next
	/// step of the backoff. Zero for the first hold.
	pub level: u32,
	/// The reply (or local reason) that put the destination on hold.
	pub reason: String,
	/// Epoch seconds the destination was first held in this run of
	/// deferrals.
	pub since: u64,
}

impl DestinationHold {
	/// Whether the hold still keeps the destination waiting at `now`.
	pub fn active(&self, now: u64) -> bool {
		self.until > now
	}
}

/// Every hold, by recipient domain.
pub type DestinationHolds = BTreeMap<String, DestinationHold>;

impl FsSpool {
	/// The holds as stored. A missing file is no hold at all.
	pub fn load_holds(&self) -> std::io::Result<DestinationHolds> {
		let path = self.path_in(Path::new(HOLDS_FILE))?;
		match crate::util::fs_walk::read(&path) {
			Ok(bytes) => serde_json::from_slice(&bytes).map_err(std::io::Error::other),
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
				Ok(DestinationHolds::new())
			}
			Err(error) => Err(error),
		}
	}

	/// Read-modify-write the holds under the spool lock and return the
	/// stored result. Nothing is written when `edit` changes nothing.
	pub fn update_holds(
		&self,
		edit: impl FnOnce(&mut DestinationHolds),
	) -> std::io::Result<DestinationHolds> {
		let _guard = self.lock()?;
		let before = self.load_holds()?;
		let mut holds = before.clone();
		edit(&mut holds);
		if holds == before {
			return Ok(holds);
		}
		let tmp =
			self.path_in(&Path::new("tmp").join(format!("{HOLDS_FILE}.{}", uuid::Uuid::now_v7())))?;
		let bytes = serde_json::to_vec(&holds).map_err(std::io::Error::other)?;
		let written = write_sync(&tmp, &bytes)
			.and_then(|()| std::fs::rename(&tmp, self.path_in(Path::new(HOLDS_FILE))?));
		if let Err(error) = written {
			let _ = std::fs::remove_file(&tmp);
			return Err(error);
		}
		Ok(holds)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn hold(until: u64) -> DestinationHold {
		DestinationHold {
			until,
			level: 0,
			reason: "421 4.7.0 slow down".into(),
			since: 100,
		}
	}

	#[test]
	fn holds_survive_reopening_the_spool() {
		let dir = tempfile::tempdir().expect("tempdir");
		let spool = FsSpool::open(dir.path()).expect("open");
		assert!(spool.load_holds().expect("load").is_empty());
		spool
			.update_holds(|holds| {
				holds.insert("example.com".into(), hold(160));
			})
			.expect("update");

		let reopened = FsSpool::open(dir.path()).expect("reopen");
		let holds = reopened.load_holds().expect("load");
		assert_eq!(holds.get("example.com"), Some(&hold(160)));
		assert!(holds["example.com"].active(159));
		assert!(!holds["example.com"].active(160));
		// The holds file is not a spool entry.
		assert!(reopened.list().expect("list").is_empty());
	}

	#[test]
	fn removing_a_hold_rewrites_the_file() {
		let dir = tempfile::tempdir().expect("tempdir");
		let spool = FsSpool::open(dir.path()).expect("open");
		spool
			.update_holds(|holds| {
				holds.insert("a.example".into(), hold(160));
				holds.insert("b.example".into(), hold(160));
			})
			.expect("update");
		spool
			.update_holds(|holds| {
				holds.remove("a.example");
			})
			.expect("update");
		let holds = spool.load_holds().expect("load");
		assert_eq!(holds.keys().collect::<Vec<_>>(), ["b.example"]);
	}
}
