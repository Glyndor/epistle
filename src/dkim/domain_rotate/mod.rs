//! Rotation of a domain's own DKIM key, the one a `[[dkim.domain]]` entry
//! names.
//!
//! Every domain rotates on its own state, under its own key directory
//! (`<data_dir>/keys/dkim/<domain>/`), so one domain's rotation never
//! touches another's records and a failure in one zone holds back only the
//! domain in it. The steps are the ones the `[dkim]` key follows
//! ([`crate::dkim::rotate`]):
//!
//! 1. The rotation is journaled before its key exists.
//! 2. A new key is made under a new selector (`own<day>`, and `ownrsa<day>`
//!    when the domain dual-signs) and its record published through a
//!    [`KeyPublisher`].
//! 3. A resolver must show the new record, with the new key, before the
//!    domain signs with it. A record that never shows withdraws the
//!    rotation and the current key keeps signing.
//! 4. The state that names the new key is saved, then the live signer of
//!    that domain switches to it.
//! 5. The replaced selector stays published for the overlap window, for
//!    mail signed just before the switch that is still queued elsewhere, and
//!    is then retired: its record withdrawn, its key file removed.
//!
//! The key the entry configures is never retired and its file never
//! removed: the entry still names it, so a lost state falls back to a key
//! that verifies. Only keys a rotation made are retired.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use crate::config::DkimDomain;
use crate::dkim::rotate::{Decision, ReloadableSigner, RotateError, RotationState};

mod journal;
mod publisher;
mod request;
mod state;

pub use publisher::{HandoffPublisher, KeyPublisher, ProviderPublisher, PublishOp};
pub use request::{last_error, pending_request, request_rotation};
pub use state::{
	DomainActive, ERROR_FILE, REQUEST_FILE, STATE_BACKUP_FILE, STATE_FILE, active_keys,
	next_selectors, read_state, state_dir,
};

/// Generates an RSA key: `(PKCS#8 PEM, DKIM TXT value)`, or why it failed.
pub(crate) type RsaKeygen = fn() -> Result<(String, String), String>;

fn rsa_2048() -> Result<(String, String), String> {
	crate::dkim::generate_rsa_key(2048).map_err(|error| error.to_string())
}

/// Rotates one domain's key: owns its state, its live signer and the
/// publisher of its records.
pub struct DomainRotator {
	data_dir: PathBuf,
	/// `<data_dir>/keys/dkim/<domain>`: the state and every key it makes.
	dir: PathBuf,
	/// The domain's `[[dkim.domain]]` entry: the key in service before the
	/// first rotation, and the one never retired.
	entry: DkimDomain,
	signer: ReloadableSigner,
	publisher: Arc<dyn KeyPublisher>,
	/// The resolver that must see a new record before it signs, and the
	/// pauses between its attempts.
	resolver: Arc<dyn crate::spf::DnsLookup>,
	waits: Vec<Duration>,
	/// Selectors a new key never takes, besides the domain's own.
	reserved: Vec<String>,
	interval: u64,
	overlap: u64,
	webhook: Option<Arc<crate::webhook::Webhook>>,
	rsa_keygen: RsaKeygen,
	/// Earliest epoch second at which a failed operator request is retried.
	request_retry_at: AtomicU64,
	#[cfg(test)]
	crash_at: Option<crate::dkim::rotate::Step>,
}

impl DomainRotator {
	/// Rotate `entry`'s key every `interval` seconds, keeping the replaced
	/// selector published `overlap` seconds. `signer` is the live signer of
	/// that domain only. A new key signs only once `resolver` shows its
	/// record; `waits` are the pauses between the lookups (the first is
	/// immediate). `Err` when the domain name cannot carry a key directory.
	pub fn new(
		data_dir: PathBuf,
		entry: DkimDomain,
		signer: ReloadableSigner,
		publisher: Arc<dyn KeyPublisher>,
		resolver: Arc<dyn crate::spf::DnsLookup>,
		waits: Vec<Duration>,
	) -> Result<Self, RotateError> {
		let dir = state_dir(&data_dir, &entry.name)?;
		Ok(DomainRotator {
			data_dir,
			dir,
			entry,
			signer,
			publisher,
			resolver,
			waits,
			reserved: Vec::new(),
			interval: crate::dkim::ROTATE_INTERVAL_DAYS * 86_400,
			overlap: crate::dkim::ROTATE_OVERLAP_DAYS * 86_400,
			webhook: None,
			rsa_keygen: rsa_2048,
			request_retry_at: AtomicU64::new(0),
			#[cfg(test)]
			crash_at: None,
		})
	}

	/// Never name a new key with one of `selectors`: every selector another
	/// key may still be published under at this domain (the `[dkim]` key's,
	/// before `dkim split --finish` retires them).
	pub fn reserving(mut self, selectors: Vec<String>) -> Self {
		self.reserved = selectors;
		self
	}

	/// Report a withdrawn rotation to this webhook.
	pub fn with_webhook(mut self, webhook: Arc<crate::webhook::Webhook>) -> Self {
		self.webhook = Some(webhook);
		self
	}

	/// Use `interval` and `overlap` (seconds) instead of the fixed ones.
	#[cfg(test)]
	pub(crate) fn with_windows(mut self, interval: u64, overlap: u64) -> Self {
		self.interval = interval;
		self.overlap = overlap;
		self
	}

	/// Use `keygen` for the RSA keys this rotator makes.
	#[cfg(test)]
	pub(crate) fn with_rsa_keygen(mut self, keygen: RsaKeygen) -> Self {
		self.rsa_keygen = keygen;
		self
	}

	/// The domain this rotator serves, lowercase.
	pub fn domain(&self) -> String {
		self.entry.name.to_ascii_lowercase()
	}

	/// The state in effect: the saved one, or for a domain that has not
	/// rotated, the configured key put in service when its file was made.
	fn effective(&self, saved: &RotationState, now: u64) -> RotationState {
		if !saved.selector.is_empty() {
			return saved.clone();
		}
		RotationState {
			selector: self.entry.selector.clone(),
			key_file: self.entry.key_file.clone(),
			rotated_at: state::configured_since(&self.entry).unwrap_or(now),
			..saved.clone()
		}
	}

	/// Run one tick at `now` (epoch seconds), doing at most one thing: finish
	/// a journaled rotation, retire a selector whose overlap has passed, or
	/// rotate when the interval has. A selector still in its overlap holds
	/// the next rotation back: the state keeps one replaced selector, and
	/// replacing it would leave its record published with nothing to retire
	/// it.
	pub async fn tick(&self, now: u64) -> Result<Decision, RotateError> {
		let mut saved = self.load_state()?;
		if saved.pending.is_some() {
			self.resume(&mut saved, now).await?;
			return Ok(Decision::Rotate);
		}
		let decision = crate::dkim::rotate::decide(
			&self.effective(&saved, now),
			now,
			self.interval,
			self.overlap,
		);
		match &decision {
			Decision::Idle => {}
			Decision::Rotate if saved.previous.is_some() => return Ok(Decision::Idle),
			Decision::Rotate => self.rotate(&mut saved, now).await?,
			Decision::Retire(selector) => self.retire(&mut saved, selector).await?,
		}
		Ok(decision)
	}

	/// Read the saved state, empty when the domain has not rotated. An
	/// unreadable state stops the rotation instead of starting a second one
	/// over it.
	fn load_state(&self) -> Result<RotationState, RotateError> {
		Ok(read_state(&self.dir)?.unwrap_or_default())
	}
}

#[cfg(test)]
mod tests;
