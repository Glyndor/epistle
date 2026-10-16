//! What the server does with the evidence on a timer: seal closed days,
//! ask for timestamp tokens (with backoff), purge what has outlived its
//! retention, and verify everything, holding transactional mail while the
//! evidence does not verify.
//!
//! The result is written to `<evidence>/status.json` for `epistle status`.
//! That file is a report, never an input: every tick verifies from scratch,
//! and the gate it sets lives in memory only.
//!
//! The gate fails closed. The service starts with it closed, and only a
//! clean verification opens it, for [`super::service::GATE_FRESH`]. A
//! verification that errors, panics, or runs past [`AUDIT_TIMEOUT`]
//! closes it; so does a seal or a token missing past its grace, which the
//! verification reports as a break.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::audit::{Options, Report, TOKEN_GRACE_SECS, verify};
use super::day::Day;
use super::key::EvidenceKey;
use super::service::EvidenceService;
use super::tsa::settings::{self, DEFAULT_TSA_ANCHOR, Settings};
use super::verify::Problem;

const STATUS_FILE: &str = "status.json";
/// How often the server runs a tick.
pub const TICK: Duration = Duration::from_secs(300);
/// The longest one verification may run before the gate closes.
pub const AUDIT_TIMEOUT: Duration = Duration::from_secs(600);

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
	audit_timeout: Duration,
	/// A verification is still running (one that timed out keeps running).
	auditing: Arc<AtomicBool>,
	/// Added to every verification, for tests of the timeout.
	#[cfg(test)]
	audit_delay: Duration,
}

/// Clears the running flag when the verification ends, even by a panic.
struct Running(Arc<AtomicBool>);

impl Drop for Running {
	fn drop(&mut self) {
		self.0.store(false, Ordering::SeqCst);
	}
}

impl Tasks {
	/// The tasks for `service`. Timestamp settings that cannot be read at
	/// start stop it: there is no last good copy to keep.
	pub fn new(service: Arc<EvidenceService>) -> std::io::Result<Self> {
		let settings = settings::load(service.root())?;
		Ok(Tasks {
			service,
			settings: Mutex::new(settings),
			audit_timeout: AUDIT_TIMEOUT,
			auditing: Arc::new(AtomicBool::new(false)),
			#[cfg(test)]
			audit_delay: Duration::ZERO,
		})
	}

	/// The same tasks with another verification timeout, for tests.
	#[cfg(test)]
	pub(crate) fn with_audit_timeout(mut self, timeout: Duration, delay: Duration) -> Self {
		self.audit_timeout = timeout;
		self.audit_delay = delay;
		self
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
		let trusted = anchors(&current);
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
		if self.auditing.swap(true, Ordering::SeqCst) {
			return self.finish(Status {
				time: now,
				held: Some("the previous evidence check is still running".into()),
				errors,
				..Status::default()
			});
		}
		let running = Running(Arc::clone(&self.auditing));
		#[cfg(test)]
		let delay = self.audit_delay;
		let audit = tokio::task::spawn_blocking(move || {
			let _running = running;
			#[cfg(test)]
			std::thread::sleep(delay);
			verify(
				&root,
				&Options {
					from: None,
					to: None,
					anchors,
					now,
				},
			)
		});
		let audited = match tokio::time::timeout(self.audit_timeout, audit).await {
			Ok(audited) => audited,
			Err(_) => {
				let reason = format!(
					"the evidence check took longer than {:?}",
					self.audit_timeout
				);
				return self.finish(Status {
					time: now,
					held: Some(reason),
					errors,
					..Status::default()
				});
			}
		};
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
				let reason = format!("the evidence check failed: {error}");
				return self.finish(Status {
					time: now,
					held: Some(reason),
					errors,
					..Status::default()
				});
			}
		};
		let (held, pending) = gate(&report, self.service.root(), now);
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
fn gate(report: &Report, root: &Path, now: u64) -> (Option<String>, Option<String>) {
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
