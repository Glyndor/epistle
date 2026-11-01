//! What the TLSA refresh remembers between runs, under
//! `<data_dir>/dns-tlsa/state.json`: the publication still owed to the
//! zone, so a DNS failure after a certificate change is retried instead of
//! forgotten, and `epistle status` can show it.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// The first wait after a failed attempt.
const FIRST_WAIT_SECS: u64 = 60;

/// The longest wait between two attempts.
const LONGEST_WAIT_SECS: u64 = 3600;

/// A publication that did not go out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pending {
	/// The `3 0 1 <sha256>` association the zone still has to receive.
	pub value: String,
	/// When the publication first failed, in seconds since the epoch.
	pub since: u64,
	/// How many attempts failed so far.
	pub attempts: u32,
	/// Not before this moment (seconds since the epoch) is it tried again.
	pub next_attempt: u64,
	/// Why the last attempt failed: text the provider or this module wrote,
	/// never a credential.
	pub reason: String,
}

/// The state of the TLSA record of one mail host.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
	/// The mail host the state is for.
	#[serde(default)]
	pub hostname: String,
	/// The publication still owed, if any.
	#[serde(default)]
	pub pending: Option<Pending>,
}

/// Where the state of a deployment lives.
pub fn path(data_dir: &Path) -> PathBuf {
	data_dir.join("dns-tlsa").join("state.json")
}

/// The wait after the `attempts`-th failed attempt: a minute, doubling,
/// never more than an hour.
pub fn wait_after(attempts: u32) -> Duration {
	let doublings = attempts.saturating_sub(1).min(6);
	Duration::from_secs((FIRST_WAIT_SECS << doublings).min(LONGEST_WAIT_SECS))
}

impl State {
	/// The state stored for `hostname`. A missing file, one that does not
	/// parse and one written for another host all give an empty state: the
	/// next refresh publishes again, which is the safe direction.
	pub fn load(data_dir: &Path, hostname: &str) -> State {
		let stored = std::fs::read_to_string(path(data_dir))
			.ok()
			.and_then(|text| serde_json::from_str::<State>(&text).ok())
			.filter(|state| state.hostname.eq_ignore_ascii_case(hostname));
		stored.unwrap_or_else(|| State {
			hostname: hostname.to_string(),
			..State::default()
		})
	}

	/// Store the state through a temporary file and a rename, so a crash
	/// never leaves half a state.
	pub fn save(&self, data_dir: &Path) -> std::io::Result<()> {
		let target = path(data_dir);
		let parent = target.parent().unwrap_or(Path::new("."));
		std::fs::create_dir_all(parent)?;
		let text = serde_json::to_string_pretty(self).map_err(std::io::Error::other)?;
		let staging = target.with_extension("json.new");
		std::fs::write(&staging, text)?;
		std::fs::rename(&staging, &target)
	}

	/// Note that publishing `value` failed at `now` for `reason`.
	pub fn fail(&mut self, value: &str, reason: String, now: u64) {
		let attempts = match &self.pending {
			Some(pending) if pending.value == value => pending.attempts.saturating_add(1),
			_ => 1,
		};
		let since = match &self.pending {
			Some(pending) if pending.value == value => pending.since,
			_ => now,
		};
		self.pending = Some(Pending {
			value: value.to_string(),
			since,
			attempts,
			next_attempt: now + wait_after(attempts).as_secs(),
			reason,
		});
	}
}
