//! The time of the last clean shutdown, so that the next start can tell a
//! gap that is a stop from a clock that jumped.
//!
//! The reference believes the wall clock at a start only near the newest
//! record (see [`super::START_SLACK_SECS`]). After a long stop the wall clock
//! is right and far from that record, and the two cases look the same from
//! outside. A server that stopped on SIGTERM wrote the time it believed
//! then, as a file in the evidence root: the next start knows how long it was
//! stopped, and believes a clock that agrees with that, within
//! [`super::MAX_KNOWN_STOP_SECS`]. The wall clock alone cannot vouch for
//! itself, so the file also holds the boot identifier of the host: the gap is
//! explained only when the host has booted since (an independent source), and a
//! clock that moved inside one boot, or a boot that cannot be read, explains
//! nothing. A start with no such file (a crash, a kill, the first start) is
//! judged as before. A monotonic counter (`CLOCK_BOOTTIME` against the wall
//! clock) would add a check inside one boot; it is left as a possible
//! improvement.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const FILE: &str = "clean-stop.json";
/// The identifier the kernel gives each boot of the host.
const BOOT_ID: &str = "/proc/sys/kernel/random/boot_id";

#[derive(Serialize, Deserialize)]
struct Stop {
	/// The time the stopping server believed, epoch seconds.
	time: u64,
	/// The boot of the host it stopped in, when it could be read.
	#[serde(default)]
	boot_id: Option<String>,
}

/// What a start knows about the last clean shutdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopNote {
	/// The host booted again since: the gap can be a stop. The time it
	/// stopped at.
	Rebooted(u64),
	/// The host has the boot it stopped in: the clock moved inside one boot,
	/// which no stop explains.
	SameBoot,
	/// The boot of the stop or of now could not be read: nothing independent
	/// of the clock says the host was down, so the stop is not used.
	BootUnknown,
}

impl StopNote {
	/// Judge a recorded stop against the boot the host is in now.
	pub fn judge(time: u64, recorded_boot: Option<&str>, current_boot: Option<&str>) -> Self {
		match (recorded_boot, current_boot) {
			(Some(then), Some(now)) if then != now => StopNote::Rebooted(time),
			(Some(_), Some(_)) => StopNote::SameBoot,
			_ => StopNote::BootUnknown,
		}
	}
}

fn path(evidence_root: &Path) -> PathBuf {
	evidence_root.join(FILE)
}

/// The boot identifier of this host, or `None` where it cannot be read (a
/// container without `/proc`, an error).
pub fn current_boot_id() -> Option<String> {
	let text = std::fs::read_to_string(BOOT_ID).ok()?;
	let id = text.trim();
	(!id.is_empty() && id.len() <= 64).then(|| id.to_string())
}

/// Record that the server stops cleanly at `time`, a time it believed, in the
/// boot `boot_id`.
pub fn record(evidence_root: &Path, time: u64, boot_id: Option<&str>) -> std::io::Result<()> {
	let stop = Stop {
		time,
		boot_id: boot_id.map(str::to_string),
	};
	let bytes = serde_json::to_vec(&stop).map_err(std::io::Error::other)?;
	crate::storage::write_secret(&path(evidence_root), &bytes)
}

/// The last clean shutdown, when one was recorded and has not been cleared by
/// a server that started since, as `(time, boot_id)`.
pub fn read(evidence_root: &Path) -> Option<(u64, Option<String>)> {
	let bytes = crate::evidence::checkpoint::read_bounded(&path(evidence_root), 4096)
		.ok()
		.flatten()?;
	serde_json::from_slice::<Stop>(&bytes)
		.ok()
		.map(|stop| (stop.time, stop.boot_id))
}

/// The recorded stop judged against the boot the host is in now.
pub fn note(evidence_root: &Path) -> Option<StopNote> {
	let (time, boot) = read(evidence_root)?;
	Some(StopNote::judge(
		time,
		boot.as_deref(),
		current_boot_id().as_deref(),
	))
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
