//! The journal of one `rotate --all` run.
//!
//! The run decides what each step will write before it writes it, and the
//! decision reaches the disk first: a step is `prepared` with the value it
//! will leave behind, then applied, then marked `done`. A run cut short at
//! any point is continued by the next one, which compares each `prepared`
//! step with what is on disk and only applies the ones that did not land,
//! so nothing is rotated twice. The journal holds digests and selectors,
//! never a secret: the new secrets live in [`super::secrets`] beside it.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The journal format this build writes and reads.
const VERSION: u32 = 1;

/// File of the run in progress, inside the rotation directory.
const CURRENT: &str = "journal.json";

/// File the last finished run is kept in, for the record.
const FINISHED: &str = "last-run.json";

/// What one step rotates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(in crate::cli::rotate) enum Kind {
	/// One management API key, by label.
	ApiKey,
	/// One app password, by account and label.
	AppPassword,
	/// The secret of the server's `[webhook]`.
	WebhookSecret,
	/// The SRS secret of one hosted domain that has its own.
	SrsSecret,
	/// The `[dkim]` key, rotated by the server on request.
	DkimKey,
	/// One domain's own `[[dkim.domain]]` key, rotated by the server.
	DkimDomainKey,
	/// The restart that makes the server read the new configuration.
	Restart,
}

/// Where a step is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(in crate::cli::rotate) enum State {
	/// Nothing decided yet.
	Pending,
	/// The value it will leave is decided and recorded; it may or may not
	/// have reached the disk.
	Prepared,
	/// Applied and checked.
	Done,
}

/// The value a prepared step leaves behind, which is how a later run tells
/// whether it landed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub(in crate::cli::rotate) enum Intent {
	/// A stored value replaced by `new`: the digest of an API key, the PHC
	/// hash of an app password, or the sha256 of a secret in the
	/// configuration. `old` is the value it replaces, when known.
	Replace { old: Option<String>, new: String },
	/// A rotation the server performs: queued while `active` was the
	/// selector in service.
	Queued { active: String },
	/// Nothing to compare: the step can run again without harm.
	Again,
}

/// One step of the run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(in crate::cli::rotate) struct Step {
	pub kind: Kind,
	/// What it rotates: the label, the domain; empty when there is one.
	pub item: String,
	/// The account an app password belongs to.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub owner: Option<String>,
	pub state: State,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub intent: Option<Intent>,
}

impl Step {
	/// A step nothing has been decided for.
	pub(in crate::cli::rotate) fn pending(kind: Kind, item: &str, owner: Option<&str>) -> Self {
		Step {
			kind,
			item: item.to_string(),
			owner: owner.map(str::to_string),
			state: State::Pending,
			intent: None,
		}
	}

	/// The name the secrets file keeps this step's new secret under.
	pub(in crate::cli::rotate) fn secret_key(&self) -> String {
		let kind = serde_json::to_value(self.kind)
			.ok()
			.and_then(|value| value.as_str().map(str::to_string))
			.unwrap_or_default();
		match &self.owner {
			Some(owner) => format!("{kind}:{owner}:{}", self.item),
			None => format!("{kind}:{}", self.item),
		}
	}
}

/// The journal of one run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(in crate::cli::rotate) struct Journal {
	pub version: u32,
	/// When the run that wrote it began, epoch seconds.
	pub started_at: u64,
	/// Every step, in the order they run.
	pub steps: Vec<Step>,
	/// What this server cannot rotate and the operator has to, found when
	/// the run was planned.
	#[serde(default)]
	pub notes: Vec<String>,
	/// When the run finished, in the archived copy.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub finished_at: Option<u64>,
}

impl Journal {
	/// A new journal for `steps`, every one pending.
	pub(in crate::cli::rotate) fn new(
		started_at: u64,
		steps: Vec<Step>,
		notes: Vec<String>,
	) -> Self {
		Journal {
			version: VERSION,
			started_at,
			steps,
			notes,
			finished_at: None,
		}
	}

	/// The unfinished run in `dir`, if there is one. A journal this build
	/// cannot read is an error, never a fresh start: starting again would
	/// rotate what the earlier run already did.
	pub(in crate::cli::rotate) fn load(dir: &Path) -> Result<Option<Self>, String> {
		let path = dir.join(CURRENT);
		let text = match std::fs::read_to_string(&path) {
			Ok(text) => text,
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
			Err(error) => return Err(format!("cannot read {}: {error}", path.display())),
		};
		let journal: Journal = serde_json::from_str(&text).map_err(|error| {
			format!(
				"{} cannot be read ({error}); it records a rotation that was cut short, so it is \
				 not replaced: move it away only once you know what it rotated",
				path.display()
			)
		})?;
		if journal.version != VERSION {
			return Err(format!(
				"{} was written by another version of epistle (format {}); finish that run with it",
				path.display(),
				journal.version
			));
		}
		Ok(Some(journal))
	}

	/// Write the journal to `dir` atomically, owner-only, and synced.
	pub(in crate::cli::rotate) fn save(&self, dir: &Path) -> Result<(), String> {
		write(&dir.join(CURRENT), self)
	}

	/// Keep the finished run as the last one and remove the current journal,
	/// so the next `rotate --all` starts a new run.
	pub(in crate::cli::rotate) fn archive(mut self, dir: &Path, now: u64) -> Result<(), String> {
		self.finished_at = Some(now);
		write(&dir.join(FINISHED), &self)?;
		let current = dir.join(CURRENT);
		std::fs::remove_file(&current)
			.map_err(|error| format!("cannot remove {}: {error}", current.display()))
	}
}

fn write(path: &Path, journal: &Journal) -> Result<(), String> {
	let bytes = serde_json::to_vec_pretty(journal).map_err(|error| error.to_string())?;
	crate::storage::write_secret(path, &bytes)
		.map_err(|error| format!("cannot write {}: {error}", path.display()))
}

/// The directory a run keeps its journal, its secrets and its lock in.
pub(in crate::cli::rotate) fn dir(data_dir: &Path) -> PathBuf {
	data_dir.join("rotate")
}
