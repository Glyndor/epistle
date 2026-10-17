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
/// Why mail is held while the clock is not believed.
const CLOCK_NOT_BELIEVED: &str =
	"the clock does not agree with the evidence log (see `epistle evidence clock accept`)";
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
	/// Whether the server believed the machine's clock at this tick. A
	/// command that runs while the server does reads it to know the clock is
	/// right, so that it does not date a record by one nobody has checked.
	#[serde(default)]
	pub clock_sound: bool,
	/// How long the last verification took, in milliseconds (zero for a tick
	/// that did not complete one). `epistle status` warns when it passes half
	/// of [`AUDIT_TIMEOUT`], since past it the gate closes.
	#[serde(default)]
	pub audit_millis: u64,
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
	/// The first wall time a test ticked at and the monotonic clock then, so
	/// that time passes by the same amount on both clocks.
	#[cfg(test)]
	following: Mutex<Option<(u64, std::time::Instant)>>,
	/// Whether the clock was believed at the tick that is running.
	sound: AtomicBool,
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
			#[cfg(test)]
			following: Mutex::new(None),
			sound: AtomicBool::new(false),
		})
	}

	/// The same tasks with another verification timeout, for tests.
	#[cfg(test)]
	pub(crate) fn with_audit_timeout(mut self, timeout: Duration, delay: Duration) -> Self {
		self.audit_timeout = timeout;
		self.audit_delay = delay;
		self
	}

	/// Run one tick at the wall-clock time `now`. What the tick acts on is
	/// not `now` but the time the shared reference believes: sealing,
	/// stamping and purging happen only when the clock agrees with it.
	pub async fn tick(&self, now: u64) -> Status {
		self.tick_at(now, std::time::Instant::now()).await
	}

	/// [`Tasks::tick`] for a test that moves time: the monotonic clock
	/// advances as far as the wall time given, so only a test that wants a
	/// jump gets one (through [`Tasks::tick_at`]).
	#[cfg(test)]
	pub(crate) async fn tick_following(&self, wall: u64) -> Status {
		let mono = {
			let mut first = self.following.lock().expect("lock");
			let (start, instant) = *first.get_or_insert((wall, std::time::Instant::now()));
			instant + Duration::from_secs(wall.saturating_sub(start))
		};
		self.tick_at(wall, mono).await
	}

	/// [`Tasks::tick`] with the monotonic clock given.
	pub(crate) async fn tick_at(&self, wall: u64, mono: std::time::Instant) -> Status {
		let time = self.service.time();
		let mut reading = time.read_at(wall, mono);
		let mut errors = Vec::new();
		let current = self.reload(&mut errors);
		if !reading.sound && super::clock_accept::take(self.service.root(), wall) {
			// The operator looked at the date and said it is right.
			time.witness(wall, mono);
			reading = time.read_at(wall, mono);
		}
		if !reading.sound && current.enabled {
			// A clock nobody agrees with: ask the timestamp authority.
			if let Some(told) = probe(&current).await {
				time.witness(told, mono);
				reading = time.read_at(wall, mono);
			}
		}
		let now = reading.time;
		self.sound.store(reading.sound, Ordering::SeqCst);
		if !reading.sound {
			errors.push(format!(
				"the clock ({}) does not agree with the evidence log or the monotonic clock: \
				 nothing is sealed, purged or expired until it does",
				Day::of_epoch(wall).name()
			));
		}
		if let Some(warning) = self.service.quota_warning() {
			errors.push(warning);
		}
		let root = self.service.root().to_path_buf();
		let enabled = current.enabled;
		let trusted = anchors(&current);
		// Sealing closes a day and purging deletes for good: neither runs on
		// a clock nobody agrees with.
		if reading.sound {
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
		}
		match super::tsa::stamp::stamp_due(&root, &current, now).await {
			Ok(pass) => {
				if let Some(told) = pass.latest {
					time.witness(told, mono);
				}
			}
			Err(error) => errors.push(format!("timestamping: {}", error.kind())),
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
			let started = std::time::Instant::now();
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
			.map(|report| (report, started.elapsed()))
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
					audit_millis: u64::try_from(self.audit_timeout.as_millis()).unwrap_or(u64::MAX),
					..Status::default()
				});
			}
		};
		let (report, took) = match audited {
			Ok(Ok(done)) => done,
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
		let (mut held, pending) = gate(&report, self.service.root(), now);
		if !reading.sound {
			// The cause comes first: whatever else the check found may only
			// be that nothing could be sealed on a clock nobody believes.
			held = Some(match held {
				Some(other) => format!("{CLOCK_NOT_BELIEVED}; {other}"),
				None => CLOCK_NOT_BELIEVED.to_string(),
			});
		}
		self.finish(Status {
			time: now,
			held,
			pending,
			acknowledged: report.acknowledged.len(),
			days: report.days,
			records: report.records,
			stamped: report.stamped,
			errors,
			clock_sound: false,
			audit_millis: u64::try_from(took.as_millis()).unwrap_or(u64::MAX),
		})
	}

	/// Read the policy and the timestamp settings again, keeping the last
	/// good ones (and saying so in `errors`) when they cannot be read.
	fn reload(&self, errors: &mut Vec<String>) -> Settings {
		self.service.reload();
		if let Some(error) = self.service.policy_error() {
			errors.push(format!(
				"retention policy unreadable, the last good one is in force: {error}"
			));
		}
		match settings::load(self.service.root()) {
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
		}
	}

	fn finish(&self, mut status: Status) -> Status {
		status.clock_sound = self.sound.load(Ordering::SeqCst);
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

/// What a timestamp authority says the time is, when one answers: a token
/// over a fixed digest, verified like any other.
async fn probe(settings: &Settings) -> Option<u64> {
	let digest = super::record::sha256(b"epistle clock probe");
	super::tsa::client::obtain(&settings.authorities, &digest)
		.await
		.ok()
		.map(|obtained| obtained.stamp.gen_time)
}

fn seal_and_sweep(
	root: &Path,
	timestamp: bool,
	anchors: &[[u8; 32]],
	now: u64,
) -> Result<Option<String>, String> {
	let key =
		EvidenceKey::load_or_create(root).map_err(|error| format!("evidence key: {error}"))?;
	// A day is sealed a margin after midnight, so a believed clock that is a
	// little ahead of the true time never seals a day that has not ended.
	super::checkpoint::seal_closed_days(
		root,
		&key,
		timestamp,
		now.saturating_sub(super::timeref::SEAL_MARGIN_SECS),
	)
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
#[cfg(test)]
#[path = "tasks_tests_clock.rs"]
mod tests_clock;
