//! Operator-requested DKIM rotation.
//!
//! The running server is the only writer of the key files, the DNS records
//! and `dkim-rotation.json`. `epistle dkim rotate` therefore never rotates by
//! itself: it drops a request file in the data directory and the server's
//! background cycle performs the rotation through the same code the automatic
//! schedule uses, then removes the file. A request survives a failed
//! publication and is retried, and survives a server that is not running
//! until it starts.

use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

use serde::{Deserialize, Serialize};

use super::{RotateError, Rotator, read_state, selector_for};

/// Request file name inside the data directory.
pub const REQUEST_FILE: &str = "dkim-rotate.request";
/// Last failure of a requested rotation, written by the server.
pub const ERROR_FILE: &str = "dkim-rotate.error";
/// Seconds to wait before retrying a requested rotation that failed.
const RETRY_AFTER: u64 = 600;

/// What the request file records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationRequest {
	/// Epoch second at which the operator asked.
	pub requested_at: u64,
}

fn path(data_dir: &Path, name: &str) -> PathBuf {
	data_dir.join(name)
}

/// Ask the server to rotate now. Asking twice keeps the first request.
pub fn request_rotation(data_dir: &Path, now: u64) -> std::io::Result<()> {
	let target = path(data_dir, REQUEST_FILE);
	if target.exists() {
		return Ok(());
	}
	let bytes = serde_json::to_vec(&RotationRequest { requested_at: now })
		.map_err(std::io::Error::other)?;
	let tmp = target.with_extension("tmp");
	std::fs::write(&tmp, bytes)?;
	std::fs::rename(&tmp, &target)
}

/// The request waiting for the server, if any. An unparsable file still counts
/// as pending (reported with `requested_at` 0): the file's presence is the
/// request.
pub fn pending_request(data_dir: &Path) -> Option<RotationRequest> {
	let bytes = std::fs::read(path(data_dir, REQUEST_FILE)).ok()?;
	Some(serde_json::from_slice(&bytes).unwrap_or(RotationRequest { requested_at: 0 }))
}

/// The reason the last attempt at a requested rotation failed, if it did.
pub fn last_error(data_dir: &Path) -> Option<String> {
	std::fs::read_to_string(path(data_dir, ERROR_FILE))
		.ok()
		.map(|text| text.trim().to_string())
}

impl Rotator {
	/// Rotate now regardless of the schedule. An older previous selector that
	/// is still inside its overlap window is retired first, because the state
	/// holds a single previous key and replacing it would leave its TXT record
	/// and key file behind. Refuses when the selector for `now` is already the
	/// active one (two rotations on the same UTC day would collide).
	pub async fn force_rotate(&self, now: u64) -> Result<(), RotateError> {
		self.sweep_temporary_files();
		let mut state = self.load_state()?;
		// A rotation a killed process left half done is the one to finish.
		if state.pending.is_some() {
			return self.resume(&mut state, now).await;
		}
		if selector_for(now) == state.selector {
			return Err(RotateError(format!(
				"selector {} is already active; a second rotation on the same UTC day would reuse its name",
				state.selector
			)));
		}
		if let Some(previous) = state.previous.clone() {
			self.retire(&mut state, &previous.selector).await?;
		}
		self.rotate(&mut state, now).await
	}

	/// Perform the operator's request if one is waiting. Returns whether a
	/// rotation happened. Success removes the request; a failure keeps it,
	/// records the reason and delays the retry.
	pub async fn serve_request(&self, now: u64) -> Result<bool, RotateError> {
		let request = path(&self.data_dir, REQUEST_FILE);
		if !request.exists() || now < self.request_retry_at.load(Ordering::Relaxed) {
			return Ok(false);
		}
		let state = self.load_state()?;
		if selector_for(now) == state.selector {
			// The schedule rotated today already, so the request is moot.
			tracing::warn!(selector = %state.selector, "requested DKIM rotation dropped: already rotated today");
			let _ = std::fs::remove_file(&request);
			return Ok(false);
		}
		match self.force_rotate(now).await {
			Ok(()) => {
				let _ = std::fs::remove_file(&request);
				let _ = std::fs::remove_file(path(&self.data_dir, ERROR_FILE));
				tracing::info!("requested DKIM rotation done");
				Ok(true)
			}
			Err(error) => {
				self.request_retry_at
					.store(now.saturating_add(RETRY_AFTER), Ordering::Relaxed);
				let _ =
					std::fs::write(path(&self.data_dir, ERROR_FILE), format!("{now} {error}\n"));
				Err(error)
			}
		}
	}

	/// One pass of the server's background work: the operator's rotation
	/// request first, then a cleanup request, then the scheduled tick when
	/// `auto_due`. A rotation just performed for a request makes the
	/// scheduled tick pointless for this pass.
	pub async fn cycle(&self, now: u64, auto_due: bool) -> Result<(), RotateError> {
		let performed = match self.serve_request(now).await {
			Ok(performed) => performed,
			Err(error) => {
				tracing::warn!(%error, "requested DKIM rotation failed; will retry");
				false
			}
		};
		if let Err(error) = self.serve_cleanup().await {
			tracing::warn!(%error, "requested DKIM cleanup left something behind");
		}
		if auto_due && !performed {
			self.tick(now).await?;
		}
		Ok(())
	}
}

/// Whether the state shows a rotation the request would collide with today.
pub fn rotated_today(data_dir: &Path, now: u64) -> Result<bool, RotateError> {
	Ok(read_state(data_dir)?.is_some_and(|state| state.selector == selector_for(now)))
}
