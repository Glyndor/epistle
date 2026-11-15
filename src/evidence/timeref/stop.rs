//! The time of the last clean shutdown, so that the next start can tell a
//! gap that is a stop from a clock that jumped.
//!
//! The reference believes the wall clock at a start only near the newest
//! record (see [`super::START_SLACK_SECS`]). After a long stop the wall clock
//! is right and far from that record, and the two cases look the same from
//! outside. A server that stopped on SIGTERM wrote the time it believed
//! then, as a file in the evidence root: the next start knows how long it was
//! stopped, and believes a clock that agrees with that, within
//! [`super::MAX_KNOWN_STOP_SECS`]. A start with no such file (a crash, a kill,
//! the first start) is judged as before.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const FILE: &str = "clean-stop.json";

#[derive(Serialize, Deserialize)]
struct Stop {
	/// The time the stopping server believed, epoch seconds.
	time: u64,
}

fn path(evidence_root: &Path) -> PathBuf {
	evidence_root.join(FILE)
}

/// Record that the server stops cleanly at `time`, a time it believed.
pub fn record(evidence_root: &Path, time: u64) -> std::io::Result<()> {
	let bytes = serde_json::to_vec(&Stop { time }).map_err(std::io::Error::other)?;
	crate::storage::write_secret(&path(evidence_root), &bytes)
}

/// The time of the last clean shutdown, when one was recorded and has not been
/// cleared by a server that started since.
pub fn read(evidence_root: &Path) -> Option<u64> {
	let bytes = crate::evidence::checkpoint::read_bounded(&path(evidence_root), 4096)
		.ok()
		.flatten()?;
	serde_json::from_slice::<Stop>(&bytes)
		.ok()
		.map(|stop| stop.time)
}

/// Forget the recorded shutdown. The server does it once it is running, so
/// that a crash later is not explained by a stop that came before it. A
/// command never does: it starts while the server is down and must not take
/// the server's explanation away.
pub fn clear(evidence_root: &Path) {
	let _ = std::fs::remove_file(path(evidence_root));
}

#[cfg(test)]
mod tests;
