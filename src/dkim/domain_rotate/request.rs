//! An operator's request to rotate one domain's key now.
//!
//! As for the `[dkim]` key, `epistle dkim rotate --domain` never rotates by
//! itself: it drops a request file in the domain's key directory and the
//! server's rotation of that domain serves it within a minute, through the
//! same steps the schedule takes.

use std::path::Path;
use std::sync::atomic::Ordering;

use super::DomainRotator;
use super::state::{ERROR_FILE, REQUEST_FILE, state_dir};
use crate::dkim::rotate::{RotateError, RotationRequest};

/// Seconds to wait before a failed request is tried again.
const RETRY_AFTER: u64 = 600;

/// Ask the server to rotate `domain`'s key now. Asking twice keeps the
/// first request.
pub fn request_rotation(data_dir: &Path, domain: &str, now: u64) -> Result<(), RotateError> {
	let dir = state_dir(data_dir, domain)?;
	crate::dkim::domain_keys::private_dir(&dir)?;
	let target = dir.join(REQUEST_FILE);
	if target.exists() {
		return Ok(());
	}
	let bytes = serde_json::to_vec(&RotationRequest { requested_at: now })
		.map_err(|error| RotateError::from_reason(error.to_string()))?;
	crate::storage::write_secret(&target, &bytes)?;
	Ok(())
}

/// The request waiting for the server for `domain`, if any. A file that
/// does not parse still counts (with `requested_at` 0): its presence is the
/// request.
pub fn pending_request(data_dir: &Path, domain: &str) -> Option<RotationRequest> {
	let bytes = std::fs::read(state_dir(data_dir, domain).ok()?.join(REQUEST_FILE)).ok()?;
	Some(serde_json::from_slice(&bytes).unwrap_or(RotationRequest { requested_at: 0 }))
}

/// Why the last rotation of `domain` failed or was withdrawn, if it did.
pub fn last_error(data_dir: &Path, domain: &str) -> Option<String> {
	let text = std::fs::read_to_string(state_dir(data_dir, domain).ok()?.join(ERROR_FILE)).ok()?;
	Some(text.trim().to_string())
}

impl DomainRotator {
	/// Rotate now, whatever the schedule says. A rotation a killed process
	/// left journaled is finished instead. Refused while the replaced
	/// selector is still in its overlap window: retiring it early would
	/// break the signatures of mail sent before the last rotation that is
	/// still queued elsewhere.
	pub async fn force_rotate(&self, now: u64) -> Result<(), RotateError> {
		let mut state = self.load_state()?;
		if state.pending.is_some() {
			return self.resume(&mut state, now).await;
		}
		if let Some(previous) = state.previous.clone() {
			if now < previous.retire_at {
				return Err(RotateError::from_reason(format!(
					"{} still publishes the replaced selector {} until epoch {}; a rotation before then would cut its overlap short",
					self.domain(),
					previous.selector,
					previous.retire_at
				)));
			}
			self.retire(&mut state, &previous.selector).await?;
		}
		self.rotate(&mut state, now).await
	}

	/// Serve the operator's request if one is waiting. Returns whether a
	/// rotation happened. Success removes the request; a failure keeps it,
	/// records the reason and delays the retry.
	pub async fn serve_request(&self, now: u64) -> Result<bool, RotateError> {
		let request = self.dir.join(REQUEST_FILE);
		if !request.exists() || now < self.request_retry_at.load(Ordering::Relaxed) {
			return Ok(false);
		}
		match self.force_rotate(now).await {
			Ok(()) => {
				let _ = std::fs::remove_file(&request);
				let _ = std::fs::remove_file(self.dir.join(ERROR_FILE));
				Ok(true)
			}
			Err(error) => {
				self.request_retry_at
					.store(now.saturating_add(RETRY_AFTER), Ordering::Relaxed);
				let _ = std::fs::write(self.dir.join(ERROR_FILE), format!("{now} {error}\n"));
				Err(error)
			}
		}
	}

	/// One pass of the server's background work for this domain: the
	/// operator's request first, then the scheduled tick when `auto_due`.
	pub async fn cycle(&self, now: u64, auto_due: bool) -> Result<(), RotateError> {
		// The provider is built once per cycle, so a credential that changed
		// is picked up without a restart.
		self.publisher.refresh();
		let performed = match self.serve_request(now).await {
			Ok(performed) => performed,
			Err(error) => {
				tracing::warn!(domain = %self.domain(), %error, "requested DKIM rotation of the domain failed; will retry");
				false
			}
		};
		if auto_due && !performed {
			self.tick(now).await?;
		}
		Ok(())
	}
}
