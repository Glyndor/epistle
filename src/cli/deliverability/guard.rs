//! The bound on test runs: one per minute per server.
//!
//! The command is short lived, so the bound lives in a file under the data
//! directory. The check and the record happen under one lock: two runs that
//! start together cannot both pass. The run is recorded only once its
//! message is queued, so a run that stopped before sending spends nothing.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::plan::Refusal;
use crate::storage::lock::FileLock;

/// The seconds that must pass between two runs.
pub(super) const MIN_INTERVAL_SECS: u64 = 60;

const STATE_FILE: &str = "deliverability-test.json";
const LOCK_FILE: &str = "deliverability-test.lock";

#[derive(Serialize, Deserialize)]
struct State {
	/// Epoch seconds of the last message queued by a run.
	last_sent: u64,
}

/// The right to send one test message, held under the lock until
/// [`Guard::record`] or until it is dropped.
pub(super) struct Guard {
	_lock: FileLock,
	state: PathBuf,
}

fn io_failure(error: impl std::fmt::Display) -> Refusal {
	Refusal {
		code: 1,
		message: format!("cannot check the rate bound: {error}"),
	}
}

impl Guard {
	/// Take the lock and check the bound against `now`: [`Self::lock`] then
	/// [`Self::checked`].
	#[cfg(test)]
	pub(super) fn acquire(data_dir: &Path, now: u64) -> Result<Self, Refusal> {
		Self::lock(data_dir)?.checked(now)
	}

	/// Take the lock that serialises the runs of one server. The clock must
	/// be read after this returns, not before: a run that waited here for
	/// another one is judged by the time it got the lock.
	pub(super) fn lock(data_dir: &Path) -> Result<Self, Refusal> {
		let lock = FileLock::acquire(&data_dir.join(LOCK_FILE)).map_err(io_failure)?;
		Ok(Self {
			_lock: lock,
			state: data_dir.join(STATE_FILE),
		})
	}

	/// Check the bound against `now`. A refusal says when the next run is
	/// allowed. A state file that cannot be read stops the run: the bound
	/// cannot be shown to hold.
	pub(super) fn checked(self, now: u64) -> Result<Self, Refusal> {
		if let Some(last) = read(&self.state).map_err(io_failure)? {
			// A last run in the future means the clock went back: nothing can be
			// said about how long ago it was, so it does not block the run.
			let next = last.saturating_add(MIN_INTERVAL_SECS);
			if last <= now && now < next {
				return Err(Refusal::policy(format!(
					"one test per minute per server: the last one was sent {} s ago; the next is allowed at {} (in {} s)",
					now.saturating_sub(last),
					crate::clock::rfc3339(next),
					next - now,
				)));
			}
		}
		Ok(self)
	}

	/// Record that a message was queued at `now`, and release the lock.
	pub(super) fn record(self, now: u64) -> std::io::Result<()> {
		let bytes = serde_json::to_vec(&State { last_sent: now }).map_err(std::io::Error::other)?;
		crate::storage::write_secret(&self.state, &bytes)
	}
}

fn read(path: &Path) -> std::io::Result<Option<u64>> {
	match std::fs::read(path) {
		Ok(bytes) => serde_json::from_slice::<State>(&bytes)
			.map(|state| Some(state.last_sent))
			.map_err(|error| {
				std::io::Error::new(
					std::io::ErrorKind::InvalidData,
					format!("{} is not readable ({error}); remove it", path.display()),
				)
			}),
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
		Err(error) => Err(error),
	}
}
