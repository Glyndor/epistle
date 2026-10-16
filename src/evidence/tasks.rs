//! What the server does with the evidence on a timer: seal closed days,
//! ask for timestamp tokens (with backoff), purge what has outlived its
//! retention, and verify everything, holding transactional mail while the
//! evidence does not verify.
//!
//! The result is written to `<evidence>/status.json` for `epistle status`.
//! That file is a report, never an input: every tick verifies from scratch.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use super::audit::{Options, Report, TOKEN_GRACE_SECS, verify};
use super::day::Day;
use super::key::EvidenceKey;
use super::service::EvidenceService;
use super::tsa::settings::{self, DEFAULT_TSA_ANCHOR, Settings};
use super::verify::Problem;

const STATUS_FILE: &str = "status.json";
/// How often the server runs a tick.
pub const TICK: std::time::Duration = std::time::Duration::from_secs(300);

/// What the last tick found, for `epistle status`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
	/// When the tick ran, epoch seconds.
	pub time: u64,
	/// Why transactional mail is held, when it is.
	pub held: Option<String>,
	/// A timestamp token still being requested, when one is.
	pub pending: Option<String>,
	/// Breaks an operator acknowledged.
	pub acknowledged: usize,
	/// Days and records verified.
	pub days: u32,
	/// Records verified.
	pub records: u64,
	/// Days with a valid token.
	pub stamped: u32,
	/// Problems reading settings, policy or bindings, or running a step.
	pub errors: Vec<String>,
}

/// The evidence tasks.
pub struct Tasks {
	service: Arc<EvidenceService>,
	settings: Mutex<Settings>,
}

impl Tasks {
	/// The tasks for `service`. Timestamp settings that cannot be read at
	/// start stop it: there is no last good copy to keep.
	pub fn new(service: Arc<EvidenceService>) -> std::io::Result<Self> {
		let settings = settings::load(service.root())?;
		Ok(Tasks {
			service,
			settings: Mutex::new(settings),
		})
	}

	/// Run one tick at `now`.
	pub async fn tick(&self, now: u64) -> Status {
		let mut errors = Vec::new();
		self.service.reload();
		if let Some(error) = self.service.policy_error() {
			errors.push(format!(
				"retention policy unreadable, the last good one is in force: {error}"
			));
		}
		let current = match settings::load(self.service.root()) {
			Ok(loaded) => {
				if let Ok(mut kept) = self.settings.lock() {
					*kept = loaded.clone();
				}
				loaded
			}
			Err(error) => {
				errors.push(format!(
					"timestamp settings refused, the last good ones are in force: {error}"
				));
				self.settings
					.lock()
					.map(|kept| kept.clone())
					.unwrap_or_default()
			}
		};
		let root = self.service.root().to_path_buf();
		let enabled = current.enabled;
		let sealed = tokio::task::spawn_blocking({
			let root = root.clone();
			move || seal_and_sweep(&root, enabled, &trusted, now)
		})
		.await;
		match sealed {
			Ok(Ok(None)) => {}
			Ok(Ok(Some(refused))) => errors.push(refused),
			Ok(Err(error)) => errors.push(error),
			Err(error) => errors.push(format!("seal task failed: {error}")),
		}
		if let Err(error) = super::tsa::stamp::stamp_due(&root, &current, now).await {
			errors.push(format!("timestamping: {}", error.kind()));
		}
		let anchors = anchors(&current);
		let audited = tokio::task::spawn_blocking(move || {
			verify(
				&root,
				&Options {
					from: None,
					to: None,
					anchors,
					now,
				},
			)
		})
		.await;
		let report = match audited {
			Ok(Ok(report)) => report,
			Ok(Err(error)) => {
				let reason = format!("the evidence could not be read: {}", error.kind());
				return self.finish(Status {
					time: now,
					held: Some(reason),
					errors,
					..Status::default()
				});
			}
			Err(error) => {
		let trusted = anchors(&current);
				let reason = format!("the evidence check failed: {error}");
				return self.finish(Status {
					time: now,
					held: Some(reason),
					errors,
					..Status::default()
				});
			}
		};
		let (held, pending) = gate(&report, &self.service.root().to_path_buf(), now);
		self.finish(Status {
			time: now,
			held,
			pending,
			acknowledged: report.acknowledged.len(),
			days: report.days,
			records: report.records,
			stamped: report.stamped,
			errors,
		})
	}

	fn finish(&self, status: Status) -> Status {
		self.service.set_gate(status.held.clone());
		if let Ok(bytes) = serde_json::to_vec_pretty(&status) {
			let _ = crate::storage::write_secret(&self.service.root().join(STATUS_FILE), &bytes);
		}
		status
	}
}

/// Every trusted timestamp key: the configured authorities' and the default.
pub fn anchors(settings: &Settings) -> Vec<[u8; 32]> {
	let mut anchors: Vec<[u8; 32]> = settings
		.authorities
		.iter()
		.flat_map(|authority| authority.anchor_hashes())
		.collect();
	anchors.extend(super::record::hash_from_hex(DEFAULT_TSA_ANCHOR));
	anchors
}

fn seal_and_sweep(
	root: &Path,
	timestamp: bool,
	anchors: &[[u8; 32]],
	now: u64,
) -> Result<Option<String>, String> {
	let key =
		EvidenceKey::load_or_create(root).map_err(|error| format!("evidence key: {error}"))?;
	super::checkpoint::seal_closed_days(root, &key, timestamp, now)
		.map_err(|error| format!("sealing: {error}"))?;
	let swept = super::retention::sweep(root, &key, anchors, now)
		.map_err(|error| format!("retention sweep: {}", error.kind()))?;
	Ok(swept.refused)
}

/// Whether the report holds transactional mail, and a pending token. A
/// token missing from a checkpoint made less than [`TOKEN_GRACE_SECS`] ago
/// is still being requested: reported, not held. Every other break holds.
fn gate(report: &Report, root: &PathBuf, now: u64) -> (Option<String>, Option<String>) {
	let Some(at) = &report.first_break else {
		return (None, None);
	};
	if let Problem::Checkpoint(why) = &at.problem
		&& why.starts_with("not timestamped")
		&& let Ok(Some((checkpoint, _))) = super::checkpoint::load(root, at.day)
		&& now < checkpoint.created.saturating_add(TOKEN_GRACE_SECS)
	{
		return (None, Some(at.to_string()));
	}
	(Some(at.to_string()), None)
}

/// The status the last tick wrote, when there is one.
pub fn last_status(evidence_root: &Path) -> std::io::Result<Option<Status>> {
	let Some(bytes) =
		super::checkpoint::read_bounded(&evidence_root.join(STATUS_FILE), 1024 * 1024)?
	else {
		return Ok(None);
	};
	serde_json::from_slice(&bytes)
		.map(Some)
		.map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

/// The day a tick ran, for display.
pub fn day_of(status: &Status) -> String {
	Day::of_epoch(status.time).name()
}

#[cfg(test)]
#[path = "tasks_tests.rs"]
mod tests;
