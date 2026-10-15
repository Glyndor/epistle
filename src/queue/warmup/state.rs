//! What the warm-up keeps across restarts, and how it is kept.
//!
//! The running server is the only writer of `<data_dir>/warmup-state.json`:
//! each group's cap, the day's use of it, the operator raise waiting for its
//! verdict, and the days already judged. Each write replaces the file
//! atomically at mode `0600`.
//!
//! The file is read back only when it is a regular file of this process's
//! user that no other user can write: a link, another user's file, or one
//! open to group or world writes could carry caps somebody else lifted.
//! Such a file, or one that does not parse, is not trusted: every group
//! goes back to its starting cap and the day counts as fully used, the most
//! restrictive reading (see [`State::distrusted`]).

use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::Group;
use super::policy::{START_CAP, Verdict};

/// The state file under the data directory.
pub const STATE_FILE: &str = "warmup-state.json";
/// The most judged days each group keeps.
pub const MAX_HISTORY: usize = 90;
/// The most senders whose share of one group's day is counted apart.
/// Senders past it share one count.
pub const MAX_SENDERS: usize = 1024;
/// The count senders past [`MAX_SENDERS`] share.
pub const OVERFLOW_SENDER: &str = "overflow";
/// The largest state file read back.
pub const MAX_STATE_BYTES: u64 = 4 * 1024 * 1024;

/// What became of an operator raise once its trial day was judged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RaiseOutcome {
	/// The trial day was not judged yet.
	Pending,
	/// The trial day was good: the raised cap stays.
	Kept,
	/// The trial day went badly: the cap went back to where it was.
	Reverted,
}

impl RaiseOutcome {
	/// `pending`, `kept` or `reverted`.
	pub fn label(self) -> &'static str {
		match self {
			RaiseOutcome::Pending => "pending",
			RaiseOutcome::Kept => "kept",
			RaiseOutcome::Reverted => "reverted",
		}
	}
}

/// An operator raise waiting for the verdict on its trial day.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Raise {
	/// The cap before the raise, which a bad trial day goes back to.
	pub from: u32,
	/// The UTC day whose verdict decides.
	pub trial_day: i64,
}

/// One judged day of one group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DayRecord {
	/// The UTC day, as days since 1970-01-01.
	pub day: i64,
	/// The cap that day; `None` when uncapped.
	pub cap: Option<u32>,
	/// Recipients the warm-up let go that day.
	pub sent: u32,
	/// Recipients a remote of the group answered for.
	pub attempted: u32,
	/// Recipients deferred for rate or reputation.
	pub deferred: u32,
	/// Permanent refusals other than policy ones.
	pub bounced: u32,
	/// Permanent `5.7.x` refusals.
	pub spam_blocks: u32,
	/// How the day went.
	pub verdict: Verdict,
	/// The cap for the next day; `None` when uncapped.
	pub next_cap: Option<u32>,
	/// What the verdict did to an operator raise, when one was on trial.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub raise: Option<RaiseOutcome>,
	/// The schedule was paused: the cap did not move.
	#[serde(default, skip_serializing_if = "std::ops::Not::not")]
	pub paused: bool,
}

/// One group's schedule and its use today.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupState {
	/// Recipients a day; `None` once the group is warmed up.
	pub cap: Option<u32>,
	/// When the next unit of the cap comes, in epoch milliseconds (see
	/// [`super::pacing`]).
	#[serde(default)]
	pub tat_ms: u64,
	/// Recipients let go today.
	#[serde(default)]
	pub sent: u32,
	/// Recipients let go today, by sender.
	#[serde(default)]
	pub senders: BTreeMap<String, u32>,
	/// An operator raise on trial.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub raise: Option<Raise>,
	/// The judged days, oldest first, at most [`MAX_HISTORY`].
	#[serde(default)]
	pub history: VecDeque<DayRecord>,
}

impl Default for GroupState {
	fn default() -> Self {
		GroupState {
			cap: Some(START_CAP),
			tat_ms: 0,
			sent: 0,
			senders: BTreeMap::new(),
			raise: None,
			history: VecDeque::new(),
		}
	}
}

impl GroupState {
	/// Keep `record`, dropping the oldest day past [`MAX_HISTORY`].
	pub fn remember(&mut self, record: DayRecord) {
		self.history.push_back(record);
		while self.history.len() > MAX_HISTORY {
			self.history.pop_front();
		}
	}

	/// The count `sender` uses today: its own, or the shared one past
	/// [`MAX_SENDERS`].
	pub fn sender_key<'a>(&self, sender: &'a str) -> &'a str {
		if self.senders.contains_key(sender) || self.senders.len() < MAX_SENDERS {
			sender
		} else {
			OVERFLOW_SENDER
		}
	}
}

/// Everything the warm-up keeps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
	/// The UTC day the use counts belong to.
	pub day: i64,
	/// The last operator order applied (see [`super::settings`]).
	#[serde(default)]
	pub applied: u64,
	/// Each group's schedule.
	#[serde(default)]
	pub groups: BTreeMap<Group, GroupState>,
}

impl State {
	/// A first state on `day`: every group at its starting cap.
	pub fn new(day: i64) -> Self {
		State {
			day,
			applied: 0,
			groups: Group::ALL
				.into_iter()
				.map(|group| (group, GroupState::default()))
				.collect(),
		}
	}

	/// The state that replaces one that cannot be trusted: every group at
	/// its starting cap, with today's share counted as spent. History is
	/// lost; mail waits for tomorrow's share instead of going out past a
	/// cap nobody can vouch for.
	pub fn distrusted(day: i64) -> Self {
		let mut state = State::new(day);
		for group in state.groups.values_mut() {
			group.sent = START_CAP;
		}
		state
	}

	/// The schedule of `group`, created at its starting cap when missing.
	pub fn group_mut(&mut self, group: Group) -> &mut GroupState {
		self.groups.entry(group).or_default()
	}

	/// The schedule of `group`, the starting one when missing.
	pub fn group(&self, group: Group) -> GroupState {
		self.groups.get(&group).cloned().unwrap_or_default()
	}
}

/// The state file under `data_dir`.
pub fn path(data_dir: &Path) -> PathBuf {
	data_dir.join(STATE_FILE)
}

/// Why a warm-up file was not read.
#[derive(Debug, thiserror::Error)]
pub enum ReadError {
	/// The file is a link, not a regular file, not ours, or writable by
	/// others.
	#[error("{0} is not a private file of this user; not trusted")]
	Insecure(String),
	/// The file is larger than any this server writes.
	#[error("{0} is larger than {MAX_STATE_BYTES} bytes; not trusted")]
	TooLarge(String),
	/// The file does not parse.
	#[error("{0} does not parse: {1}")]
	Corrupt(String, String),
	/// The file could not be read.
	#[error("{0}: {1}")]
	Io(String, std::io::Error),
}

/// Read the bytes of the private file at `path`, or `None` when there is
/// none. The file is opened without following a link and checked through
/// the open descriptor.
pub fn read_private(path: &Path, limit: u64) -> Result<Option<Vec<u8>>, ReadError> {
	use std::io::Read;
	let shown = path.display().to_string();
	let mut options = std::fs::OpenOptions::new();
	options.read(true);
	#[cfg(unix)]
	{
		use std::os::unix::fs::OpenOptionsExt;
		options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
	}
	let file = match options.open(path) {
		Ok(file) => file,
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
		#[cfg(unix)]
		Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
			return Err(ReadError::Insecure(shown));
		}
		Err(error) => return Err(ReadError::Io(shown, error)),
	};
	let meta = file
		.metadata()
		.map_err(|error| ReadError::Io(shown.clone(), error))?;
	if !meta.is_file() || !private(&meta) {
		return Err(ReadError::Insecure(shown));
	}
	if meta.len() > limit {
		return Err(ReadError::TooLarge(shown));
	}
	let mut bytes = Vec::new();
	file.take(limit + 1)
		.read_to_end(&mut bytes)
		.map_err(|error| ReadError::Io(shown.clone(), error))?;
	if bytes.len() as u64 > limit {
		return Err(ReadError::TooLarge(shown));
	}
	Ok(Some(bytes))
}

/// Whether a file is this process's user's and nobody else may write it.
#[cfg(unix)]
fn private(meta: &std::fs::Metadata) -> bool {
	use std::os::unix::fs::MetadataExt;
	// SAFETY: geteuid takes no arguments and cannot fail.
	let euid = unsafe { libc::geteuid() };
	meta.uid() == euid && meta.mode() & 0o022 == 0
}

#[cfg(not(unix))]
fn private(_meta: &std::fs::Metadata) -> bool {
	true
}

/// Read the state under `data_dir`; `None` when there is none yet.
pub fn load(data_dir: &Path) -> Result<Option<State>, ReadError> {
	let file = path(data_dir);
	let Some(bytes) = read_private(&file, MAX_STATE_BYTES)? else {
		return Ok(None);
	};
	let mut state: State = serde_json::from_slice(&bytes)
		.map_err(|error| ReadError::Corrupt(file.display().to_string(), error.to_string()))?;
	// A file written by hand may carry more than this server keeps.
	for group in state.groups.values_mut() {
		while group.history.len() > MAX_HISTORY {
			group.history.pop_front();
		}
		if group.senders.len() > MAX_SENDERS + 1 {
			return Err(ReadError::Corrupt(
				file.display().to_string(),
				"too many senders".into(),
			));
		}
	}
	Ok(Some(state))
}

/// Write `state` under `data_dir`, replacing the file atomically at mode
/// `0600`.
pub fn save(data_dir: &Path, state: &State) -> std::io::Result<()> {
	let bytes = serde_json::to_vec_pretty(state).map_err(std::io::Error::other)?;
	crate::storage::write_secret(&path(data_dir), &bytes)
}

#[cfg(test)]
#[path = "state_tests.rs"]
mod tests;
