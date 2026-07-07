//! Automatic DKIM key rotation.
//!
//! On a schedule the server generates a fresh ed25519 key under a new selector,
//! publishes its public key as a DNS TXT record, and swaps the live signer over
//! to it. The previous selector's TXT stays published for an overlap window so
//! mail signed just before the switch still verifies, then it is retired.
//!
//! The rotation *decision* ([`decide`]) is pure and unit-tested; the I/O — key
//! generation, the DNS upsert/delete, the signer swap, and persisting state —
//! is the thin glue in [`Rotator::tick`].

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

/// The previous selector, kept published until its overlap window elapses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Previous {
	/// The retired selector whose TXT is still published.
	pub selector: String,
	/// Epoch second at/after which the old TXT may be deleted.
	pub retire_at: u64,
}

/// Persisted rotation state (`<data_dir>/dkim-rotation.json`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationState {
	/// The active selector.
	pub selector: String,
	/// The active key file (PKCS#8 PEM), relative to the data directory.
	pub key_file: PathBuf,
	/// When the active key was put into service (epoch seconds).
	pub rotated_at: u64,
	/// A retired selector still within its overlap window, if any.
	pub previous: Option<Previous>,
}

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

/// Drives DKIM rotation: owns the state file, the live signer handle, and the
/// DNS publisher.
pub struct Rotator {
	state_path: PathBuf,
	data_dir: PathBuf,
	signer: ReloadableSigner,
	provider: Arc<dyn DnsProvider>,
	zone: String,
	signing_domain: String,
	interval: u64,
	overlap: u64,
}

impl Rotator {
	/// Build a rotator. `zone` is the DNS zone to publish under and
	/// `signing_domain` the `d=` domain (its `_domainkey` host).
	#[allow(clippy::too_many_arguments)]
	pub fn new(
		data_dir: PathBuf,
		signer: ReloadableSigner,
		provider: Arc<dyn DnsProvider>,
		zone: String,
		signing_domain: String,
		interval: u64,
		overlap: u64,
	) -> Self {
		let state_path = data_dir.join("dkim-rotation.json");
		Rotator {
			state_path,
			data_dir,
			signer,
			provider,
			zone,
			signing_domain,
			interval,
			overlap,
		}
	}

	/// Load persisted state, or a default (empty) state.
	fn load_state(&self) -> RotationState {
		std::fs::read(&self.state_path)
			.ok()
			.and_then(|bytes| serde_json::from_slice(&bytes).ok())
			.unwrap_or_default()
	}

	fn save_state(&self, state: &RotationState) -> std::io::Result<()> {
		let bytes = serde_json::to_vec_pretty(state).map_err(std::io::Error::other)?;
		std::fs::write(&self.state_path, bytes)
	}

	/// The DNS record name for a selector's public key.
	fn record_name(&self, selector: &str) -> String {
		format!("{selector}._domainkey.{}", self.signing_domain)
	}

	/// Run one rotation tick at `now` (epoch seconds), performing at most one
	/// action. Returns the action taken.
	pub async fn tick(&self, now: u64) -> Result<Decision, RotateError> {
		let mut state = self.load_state();
		let decision = decide(&state, now, self.interval, self.overlap);
		match &decision {
			Decision::Idle => {}
			Decision::Rotate => {
				let selector = selector_for(now);
				// A same-day re-run must not collide with the active selector.
				if selector == state.selector {
					return Ok(Decision::Idle);
				}
				let (pem, txt) = super::generate_key().map_err(|e| RotateError(e.to_string()))?;
				let key_file = self.data_dir.join(format!("dkim-{selector}.key"));
				write_key(&key_file, &pem)?;
				self.provider
					.upsert(&self.zone, txt_record(&self.record_name(&selector), &txt))
					.await
					.map_err(|e| RotateError(e.to_string()))?;
				let signer =
					Signer::load(&selector, &key_file).map_err(|e| RotateError(e.to_string()))?;
				self.signer.reload(Arc::new(signer));
				// Retire the just-replaced selector after the overlap window.
				let previous = (!state.selector.is_empty()).then(|| Previous {
					selector: state.selector.clone(),
					retire_at: now.saturating_add(self.overlap),
				});
				state = RotationState {
					selector,
					key_file,
					rotated_at: now,
					previous,
				};
				self.save_state(&state)?;
			}
			Decision::Retire(selector) => {
				self.provider
					.delete(&self.zone, txt_record(&self.record_name(selector), ""))
					.await
					.map_err(|e| RotateError(e.to_string()))?;
				state.previous = None;
				self.save_state(&state)?;
			}
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
	}
}

/// Write a new key file with `0600` permissions (private key material).
///
/// The file is created with the restrictive mode from the start — never written
/// world/group-readable and then tightened — so the private key never exists
/// with permissive bits, even briefly. The path carries a fresh per-rotation
/// selector, so it must not already exist; `create_new` makes that an error
/// rather than overwriting (fail closed: rotation is retried on the next tick).
fn write_key(path: &std::path::Path, pem: &str) -> std::io::Result<()> {
	use std::io::Write;

	let mut options = std::fs::OpenOptions::new();
	options.write(true).create_new(true);
	#[cfg(unix)]
	{
		use std::os::unix::fs::OpenOptionsExt;
		options.mode(0o600);
	}
	options.open(path)?.write_all(pem.as_bytes())
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
