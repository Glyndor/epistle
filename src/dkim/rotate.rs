//! Automatic DKIM key rotation.
//!
//! On a schedule the server generates a fresh ed25519 key under a new selector,
//! publishes its public key as a DNS TXT record, and swaps the live signer over
//! to it. The previous selector's TXT stays published for an overlap window so
//! mail signed just before the switch still verifies, then it is retired.
//!
//! When the server also signs with RSA (dual signing), the same rotation
//! generates a fresh RSA key under its own selector (`rsa<day>`). Both keys
//! are journaled in one [`Pending`], published and confirmed in every
//! signing domain, and switch together in the one save that commits the
//! rotation: the signer never pairs a new key with one nobody can verify,
//! and a withdrawal or a retirement removes both.
//!
//! The rotation *decision* ([`decide`]) is pure and unit-tested; the I/O — key
//! generation, the DNS upsert/delete, the signer swap, and persisting state —
//! is the thin glue in [`Rotator::tick`].
//!
//! Each rotation is written to the state as [`Pending`] before its key
//! exists and committed by the one save that names the new key as active,
//! so a process killed at any step leaves a state the next tick completes
//! or rolls back (`rotate_steps.rs` lists the steps).

use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};

use super::sign::Signer;
use crate::dns::provider::{DnsProvider, DnsRecord, RecordKind};

/// A hot-swappable DKIM signer: the rotation task replaces the active signer
/// without dropping in-flight deliveries. Mirrors `tls::ReloadableAcceptor`.
#[derive(Clone)]
pub struct ReloadableSigner {
	inner: Arc<RwLock<Arc<Signer>>>,
}

impl ReloadableSigner {
	/// Wrap an initial signer.
	pub fn new(signer: Arc<Signer>) -> Self {
		ReloadableSigner {
			inner: Arc::new(RwLock::new(signer)),
		}
	}

	/// The current signer (cheap clone; shares the key via `Arc`).
	pub fn current(&self) -> Arc<Signer> {
		Arc::clone(&self.inner.read().expect("signer lock"))
	}

	/// Swap in a freshly rotated signer.
	pub fn reload(&self, signer: Arc<Signer>) {
		*self.inner.write().expect("signer lock") = signer;
	}
}

/// An RSA dual-signing key that a rotation put in service, retired or is
/// rotating to: its selector and its key file (PKCS#8 PEM).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RsaKey {
	/// Selector published at `<selector>._domainkey.<domain>`.
	pub selector: String,
	/// Key file, absolute or relative to the data directory.
	pub key_file: PathBuf,
}

/// The previous selector, kept published until its overlap window elapses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Previous {
	/// The retired selector whose TXT is still published.
	pub selector: String,
	/// The retired selector's key file (PKCS#8 PEM), absolute path. Recorded
	/// at rotation time so [`Rotator`] can remove it once the TXT is taken
	/// down, instead of leaving every retired signing key on disk forever.
	/// `[serde(default)]` lets state written before this field existed still
	/// load; an empty path is treated as "no file to remove" rather than as
	/// a path to delete.
	#[serde(default)]
	pub key_file: PathBuf,
	/// Epoch second at/after which the old TXT may be deleted.
	pub retire_at: u64,
	/// The RSA key the same rotation replaced, retired with the selector
	/// above. Absent when no RSA key was rotated out, or when the one
	/// replaced was the configured key, which is left as it is.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub rsa: Option<RsaKey>,
}

/// A rotation begun and not yet committed or withdrawn: the journal entry
/// written before its key exists, so a process killed at any later step
/// leaves enough for the next tick to finish it or take it back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pending {
	/// The selector being rotated to.
	pub selector: String,
	/// Where its key file is (or is about to be) written, absolute.
	pub key_file: PathBuf,
	/// The signing domains its TXT may have been published under.
	pub domains: Vec<String>,
	/// Epoch second at which the rotation began.
	pub started_at: u64,
	/// Why the rotation is being taken back, once it is: from then on its
	/// records and key are only removed, never published again.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub withdrawing: Option<String>,
	/// The RSA key rotated in the same step, when the server dual-signs.
	/// It is published, confirmed, committed and withdrawn together with
	/// the ed25519 key above.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub rsa: Option<RsaKey>,
}

/// Persisted rotation state (`<data_dir>/dkim-rotation.json`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationState {
	/// The active selector.
	pub selector: String,
	/// The active key file (PKCS#8 PEM), absolute or relative to the data directory.
	pub key_file: PathBuf,
	/// When the active key was put into service (epoch seconds).
	pub rotated_at: u64,
	/// A retired selector still within its overlap window, if any.
	pub previous: Option<Previous>,
	/// A rotation in progress. The selector above keeps signing until it is
	/// committed. Absent in state written before rotations were journaled.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub pending: Option<Pending>,
	/// The RSA key a rotation put in service. Absent before the first
	/// rotation that covered RSA: the configured RSA key signs then.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub rsa: Option<RsaKey>,
}

impl RotationState {
	/// Whether the state names no key in service and journals no rotation:
	/// the state of an install that has not rotated yet.
	///
	/// Such a state is not worth keeping on disk (a rotation that never
	/// put a key in service leaves none behind) and it is not a corrupt
	/// file either: the server reads it as an absent state and signs with
	/// the configured key.
	pub fn is_empty(&self) -> bool {
		self.selector.is_empty()
			&& self.pending.is_none()
			&& self.previous.is_none()
			&& self.rsa.is_none()
	}
}

/// File name of the persisted rotation state inside the data directory.
pub const STATE_FILE: &str = "dkim-rotation.json";

/// A DKIM key currently in service: its selector and an absolute key path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveKey {
	/// Selector published at `<selector>._domainkey.<domain>`.
	pub selector: String,
	/// Private key file (PKCS#8 PEM), resolved against the data directory.
	pub key_file: PathBuf,
}

/// File name of the last good rotation state, the one [`STATE_FILE`] held
/// before its latest save.
pub const STATE_BACKUP_FILE: &str = "dkim-rotation.json.bak";

/// Read `<data_dir>/dkim-rotation.json`. `Ok(None)` when the file does
/// not exist and when it holds an empty state (one that names no key in
/// service): an empty state is the state of an install that has not
/// rotated yet, not a corrupt file. An unreadable or invalid file is an
/// error, because guessing the configured key would show (or sign with) a
/// selector that is not in service.
pub fn read_state(data_dir: &std::path::Path) -> Result<Option<RotationState>, RotateError> {
	parse_state(&data_dir.join(STATE_FILE))
}

fn parse_state(path: &std::path::Path) -> Result<Option<RotationState>, RotateError> {
	let bytes = match std::fs::read(path) {
		Ok(bytes) => bytes,
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
		Err(error) => return Err(RotateError(format!("read {}: {error}", path.display()))),
	};
	decode_state(path, &bytes)
}

/// Parse the bytes of a state file read from `path` (named in errors).
///
/// `Ok(None)` when the bytes hold an empty state: a state that names no
/// key in service and journals no rotation. A rotation journaled before
/// its key was in service still loads (its `pending` entry is what the
/// next tick finishes), but a state that names no selector and keeps a
/// retired key is inconsistent, and it is reported as such.
fn decode_state(
	path: &std::path::Path,
	bytes: &[u8],
) -> Result<Option<RotationState>, RotateError> {
	let state: RotationState = serde_json::from_slice(bytes)
		.map_err(|error| RotateError(format!("parse {}: {error}", path.display())))?;
	if state.selector.is_empty() {
		if state.pending.is_some() {
			return Ok(Some(state));
		}
		if state.previous.is_some() || state.rsa.is_some() {
			return Err(RotateError(format!(
				"{} has an empty selector",
				path.display()
			)));
		}
		return Ok(None);
	}
	Ok(Some(state))
}

/// When the state cannot be read but [`STATE_BACKUP_FILE`] can, the reason
/// the state was rejected: the last good state is then what signs, and
/// rotation stays stopped until the operator restores the file.
pub fn state_fallback(data_dir: &std::path::Path) -> Option<String> {
	let error = read_state(data_dir).err()?;
	matches!(parse_state(&data_dir.join(STATE_BACKUP_FILE)), Ok(Some(_))).then(|| error.to_string())
}

/// The one answer to "which ed25519 key is in service": the rotation state
/// when it exists, the configured key otherwise. Startup, `dns-records`,
/// `verify-dns` and `dkim show` all call this, so they cannot disagree.
///
/// A state that cannot be read must not stop signing, so the last good
/// state stands in for it when [`STATE_BACKUP_FILE`] reads; without one
/// the error stands. The backup names a key whose TXT is still published:
/// it is at most one save behind, and a retired selector leaves the state
/// only after its records and key are gone.
pub fn active_ed25519(
	dkim: &crate::config::Dkim,
	data_dir: &std::path::Path,
) -> Result<ActiveKey, RotateError> {
	Ok(match signing_state(data_dir)? {
		// A state that names no key in service (a rotation journaled
		// before its key was ready) leaves the configured key signing.
		Some(state) if !state.selector.is_empty() => ActiveKey {
			selector: state.selector,
			key_file: data_dir.join(state.key_file),
		},
		_ => ActiveKey {
			selector: dkim.selector.clone(),
			key_file: dkim.key_file.clone(),
		},
	})
}

/// The RSA dual-signing key in service, the same way [`active_ed25519`]
/// answers for ed25519: `None` when `[dkim]` does not set both
/// `rsa_selector` and `rsa_key_file` (dual signing is off), the key the
/// last rotation put in service when the state names one, the configured
/// key otherwise.
pub fn active_rsa(
	dkim: &crate::config::Dkim,
	data_dir: &std::path::Path,
) -> Result<Option<ActiveKey>, RotateError> {
	let (Some(selector), Some(key_file)) = (&dkim.rsa_selector, &dkim.rsa_key_file) else {
		return Ok(None);
	};
	Ok(Some(match signing_state(data_dir)?.and_then(|s| s.rsa) {
		Some(rsa) => ActiveKey {
			selector: rsa.selector,
			key_file: data_dir.join(rsa.key_file),
		},
		None => ActiveKey {
			selector: selector.clone(),
			key_file: key_file.clone(),
		},
	}))
}

/// The state the signer follows: [`read_state`], or the last good copy in
/// [`STATE_BACKUP_FILE`] when the state cannot be read.
fn signing_state(data_dir: &std::path::Path) -> Result<Option<RotationState>, RotateError> {
	match read_state(data_dir) {
		Ok(state) => Ok(state),
		Err(error) => match parse_state(&data_dir.join(STATE_BACKUP_FILE)) {
			Ok(Some(backup)) => {
				tracing::warn!(
					%error,
					selector = %backup.selector,
					"DKIM rotation state is unreadable; signing with the last good state in {STATE_BACKUP_FILE}",
				);
				Ok(Some(backup))
			}
			_ => Err(error),
		},
	}
}

/// The interval between automatic DKIM key rotations, in days.
///
/// Rotation is a security property of the server, not a per-deployment
/// preference; this is why the value is fixed in code rather than read from
/// the config file. Aligned with the TLS certificate cycle, which is also
/// 90 days.
pub const ROTATE_INTERVAL_DAYS: u64 = 90;

/// Days the retired selector's TXT stays published after a rotation so
/// in-flight mail still verifies.
///
/// Sized to cover the remote-server retry queue: a message signed just
/// before rotation can sit in a remote retry queue for four or five days,
/// so the previous 7-day window left no margin. 14 covers that and still
/// keeps the DNS footprint bounded.
pub const ROTATE_OVERLAP_DAYS: u64 = 14;

/// What a rotation tick should do at a given time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
	/// Nothing is due.
	Idle,
	/// Generate a new key/selector and switch to it.
	Rotate,
	/// Retire the named previous selector (its overlap window has elapsed).
	Retire(String),
}

/// Decide what to do at `now`, given the rotation `interval` and `overlap`
/// windows (seconds). Retiring an expired previous selector takes precedence so
/// stale records are cleaned up promptly; otherwise rotate once the interval has
/// elapsed. An empty state (no selector yet) rotates immediately to bootstrap.
pub fn decide(state: &RotationState, now: u64, interval: u64, _overlap: u64) -> Decision {
	if let Some(previous) = &state.previous
		&& now >= previous.retire_at
	{
		return Decision::Retire(previous.selector.clone());
	}
	if state.selector.is_empty() || now.saturating_sub(state.rotated_at) >= interval {
		return Decision::Rotate;
	}
	Decision::Idle
}

/// A fresh, unique-per-rotation selector derived from the rotation day.
pub fn selector_for(now: u64) -> String {
	format!("ed{}", now / 86_400)
}

/// The RSA selector a rotation on the day of `now` puts in service.
pub fn rsa_selector_for(now: u64) -> String {
	format!("rsa{}", now / 86_400)
}

/// Drives DKIM rotation: owns the state file, the live signer handle, and the
/// DNS publisher.
pub struct Rotator {
	state_path: PathBuf,
	data_dir: PathBuf,
	signer: ReloadableSigner,
	provider: Arc<dyn DnsProvider>,
	zone: String,
	signing_domains: Vec<String>,
	interval: u64,
	overlap: u64,
	/// Earliest epoch second at which a failed operator request is retried.
	request_retry_at: std::sync::atomic::AtomicU64,
	/// The resolver that must see a new selector before it signs, and the
	/// waits between its attempts.
	publication_check: Option<(Arc<dyn crate::spf::DnsLookup>, Vec<std::time::Duration>)>,
	/// Where a rotation that could not be confirmed is reported.
	webhook: Option<Arc<crate::webhook::Webhook>>,
	/// Selectors outside the state that are never orphans.
	keep: Vec<String>,
	/// Makes the RSA key of a dual-signing rotation.
	rsa_keygen: rsa::RsaKeygen,
	/// The step at which a test stops the rotator.
	#[cfg(test)]
	crash_at: Option<steps::Step>,
}

impl Rotator {
	/// Build a rotator. `zone` is the DNS zone to publish under and
	/// `signing_domains` the `d=` domains (their `_domainkey` hosts) that the
	/// relay can sign mail for and that sit inside the zone. The list is
	/// deduplicated and preserves the caller's order. An empty list is
	/// permitted: rotation will run, but no DKIM records will be published
	/// (the caller is expected to have logged a startup warning naming the
	/// out-of-zone domains that caused the empty result).
	#[allow(clippy::too_many_arguments)]
	pub fn new(
		data_dir: PathBuf,
		signer: ReloadableSigner,
		provider: Arc<dyn DnsProvider>,
		zone: String,
		signing_domains: Vec<String>,
		interval: u64,
		overlap: u64,
	) -> Self {
		let mut seen = std::collections::HashSet::new();
		let signing_domains = signing_domains
			.into_iter()
			.filter(|d| seen.insert(d.clone()))
			.collect();
		let state_path = data_dir.join("dkim-rotation.json");
		Rotator {
			state_path,
			data_dir,
			signer,
			provider,
			zone,
			signing_domains,
			interval,
			overlap,
			request_retry_at: std::sync::atomic::AtomicU64::new(0),
			publication_check: None,
			webhook: None,
			keep: Vec::new(),
			rsa_keygen: rsa::rsa_2048,
			#[cfg(test)]
			crash_at: None,
		}
	}

	/// Confirm through `resolver` that a new selector's TXT is visible,
	/// with the right key, before the signer switches to it. `waits` are
	/// the pauses between attempts; the first query is immediate.
	pub fn with_publication_check(
		mut self,
		resolver: Arc<dyn crate::spf::DnsLookup>,
		waits: Vec<std::time::Duration>,
	) -> Self {
		self.publication_check = Some((resolver, waits));
		self
	}

	/// Report a rotation whose key never became visible to this webhook.
	pub fn with_webhook(mut self, webhook: Arc<crate::webhook::Webhook>) -> Self {
		self.webhook = Some(webhook);
		self
	}

	/// Whether `name` sits inside `zone` (equals it or is a subdomain of it),
	/// the way [`crate::dns::provider::ScopedSecret`] authorises a record
	/// name. Case-insensitive on both sides so uppercase DNS queries still
	/// match a lowercase zone.
	pub fn is_in_zone(name: &str, zone: &str) -> bool {
		let name = name.to_ascii_lowercase();
		let zone = zone.to_ascii_lowercase();
		name == zone || name.ends_with(&format!(".{zone}"))
	}

	/// Load persisted state, or a default (empty) state when no file exists.
	/// An unreadable or invalid file is an error: treating it as empty would
	/// bootstrap a second key and orphan the published one.
	fn load_state(&self) -> Result<RotationState, RotateError> {
		Ok(read_state(&self.data_dir)?.unwrap_or_default())
	}

	/// Replace the state file atomically and durably: a uniquely named
	/// temporary file is synced, renamed over the state and the directory is
	/// synced, so neither a concurrent `dkim show`, a restart nor a power
	/// loss right after the save reads a half-written or missing file. The
	/// state being replaced, when it reads, is kept first as
	/// [`STATE_BACKUP_FILE`].
	///
	/// A state that names no key in service is not written at all: the file
	/// is removed instead, so a rotation that never put a key in service
	/// leaves the data directory as a fresh install looks. The server reads
	/// such a state as an absent one, so the file was never worth keeping.
	fn save_state(&self, state: &RotationState) -> std::io::Result<()> {
		if state.is_empty() {
			remove_state_file(&self.state_path);
			return Ok(());
		}
		let bytes = serde_json::to_vec_pretty(state).map_err(std::io::Error::other)?;
		if let Ok(current) = std::fs::read(&self.state_path)
			&& matches!(decode_state(&self.state_path, &current), Ok(Some(_)))
		{
			crate::storage::write_secret(&self.data_dir.join(STATE_BACKUP_FILE), &current)?;
		}
		crate::storage::write_secret(&self.state_path, &bytes)
	}

	/// The DNS record name for a selector's public key at `domain`.
	fn record_name(selector: &str, domain: &str) -> String {
		format!("{selector}._domainkey.{domain}")
	}

	/// Run one rotation tick at `now` (epoch seconds), performing at most one
	/// action. Returns the action taken.
	pub async fn tick(&self, now: u64) -> Result<Decision, RotateError> {
		self.sweep_temporary_files();
		let mut state = self.load_state()?;
		// A rotation a killed process left half done comes first: until it
		// is committed or withdrawn nothing else may touch the state.
		if state.pending.is_some() {
			self.resume(&mut state, now).await?;
			return Ok(Decision::Rotate);
		}
		let decision = decide(&state, now, self.interval, self.overlap);
		match &decision {
			Decision::Idle => {}
			Decision::Rotate => {
				// A same-day re-run must not collide with the active selector.
				if selector_for(now) == state.selector {
					return Ok(Decision::Idle);
				}
				self.rotate(&mut state, now).await?;
			}
			Decision::Retire(selector) => self.retire(&mut state, selector).await?,
		}
		Ok(decision)
	}
}

/// A TXT [`DnsRecord`] for a name/value.
fn txt_record(name: &str, value: &str) -> DnsRecord {
	DnsRecord {
		name: name.to_string(),
		kind: RecordKind::Txt,
		value: value.to_string(),
		ttl: 300,
		proxied: None,
	}
}

/// Remove a state file that names no key. Best effort: the server reads
/// an empty state as an absent one, so a file that stays behind is
/// harmless; the failure is logged rather than allowed to break the
/// rotation that is finishing.
fn remove_state_file(path: &std::path::Path) {
	if let Err(error) = std::fs::remove_file(path)
		&& error.kind() != std::io::ErrorKind::NotFound
	{
		tracing::warn!(
			%error,
			path = %path.display(),
			"cannot remove the empty DKIM rotation state file"
		);
	}
}

/// A rotation failure (logged; rotation is retried on the next tick).
#[derive(Debug, thiserror::Error)]
#[error("dkim rotation: {0}")]
pub struct RotateError(String);

impl From<std::io::Error> for RotateError {
	fn from(error: std::io::Error) -> Self {
		RotateError(error.to_string())
	}
}

#[cfg(test)]
#[path = "rotate_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "rotate_tests_publication.rs"]
mod tests_publication;

#[cfg(test)]
#[path = "rotate_tests_signing.rs"]
mod tests_signing;

#[cfg(test)]
#[path = "rotate_tests_multidomain.rs"]
mod tests_multidomain;

#[path = "rotate_steps.rs"]
mod steps;

#[cfg(test)]
#[path = "rotate_tests_crash.rs"]
mod tests_crash;

#[cfg(test)]
#[path = "rotate_tests_resume.rs"]
mod tests_resume;

#[path = "rotate_orphans.rs"]
mod orphans;
pub use orphans::{CLEANUP_FILE, Orphans, find_orphans, request_cleanup};

#[cfg(test)]
#[path = "rotate_tests_orphans.rs"]
mod tests_orphans;

#[path = "rotate_publication.rs"]
mod publication;

#[path = "rotate_rsa.rs"]
mod rsa;
pub use publication::publication_waits;

#[path = "rotate_request.rs"]
mod request;
pub use request::{
	ERROR_FILE, REQUEST_FILE, RotationRequest, last_error, pending_request, request_rotation,
	rotated_today,
};

#[cfg(test)]
#[path = "rotate_tests_active.rs"]
mod tests_active;

#[cfg(test)]
#[path = "rotate_tests_request.rs"]
mod tests_request;

#[cfg(test)]
#[path = "rotate_tests_rsa_lab.rs"]
mod tests_rsa_lab;

#[cfg(test)]
#[path = "rotate_tests_crash_rsa.rs"]
mod tests_crash_rsa;

#[cfg(test)]
#[path = "rotate_tests_rsa.rs"]
mod tests_rsa;

#[cfg(test)]
#[path = "rotate_tests_empty_state.rs"]
mod tests_empty_state;
