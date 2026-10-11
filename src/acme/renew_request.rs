//! Operator-requested certificate renewal.
//!
//! The server owns the ACME account key and the HTTP-01 challenge listener, so
//! `epistle tls renew` cannot issue by itself. It drops a request file under
//! `<data_dir>/acme/` and the server's renewal loop, which wakes every minute,
//! serves it through the same issuance path as the schedule. A request
//! survives a failed issuance and a server that is down.

use std::path::{Path, PathBuf};
use std::pin::Pin;

use serde::{Deserialize, Serialize};

use super::client::AcmeError;
use super::renew::needs_renewal;

/// Request file name under `<data_dir>/acme/`.
pub const REQUEST_FILE: &str = "renew.request";
/// Last failure of a requested renewal, written by the server.
pub const ERROR_FILE: &str = "renew.error";
/// Seconds before a failed operator request is tried again (CAs rate-limit
/// failed validations, so this is deliberately slow).
const REQUEST_RETRY: u64 = 3600;
/// Seconds before a failed scheduled renewal is tried again.
const SCHEDULED_RETRY: u64 = 12 * 3600;

/// What the request file records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenewRequest {
	/// Renew even when the certificate is not inside its renewal window.
	pub force: bool,
	/// Epoch second at which the operator asked.
	pub requested_at: u64,
}

fn file(data_dir: &Path, name: &str) -> PathBuf {
	data_dir.join("acme").join(name)
}

/// Ask the server to renew now. A second request keeps the first timestamp
/// and `force` once either asked for it.
pub fn request_renewal(data_dir: &Path, force: bool, now: u64) -> std::io::Result<()> {
	let previous = pending_request(data_dir);
	let request = RenewRequest {
		force: force || previous.as_ref().is_some_and(|p| p.force),
		requested_at: previous.map_or(now, |p| p.requested_at),
	};
	let target = file(data_dir, REQUEST_FILE);
	if let Some(parent) = target.parent() {
		std::fs::create_dir_all(parent)?;
	}
	let tmp = target.with_extension("tmp");
	std::fs::write(
		&tmp,
		serde_json::to_vec(&request).map_err(std::io::Error::other)?,
	)?;
	std::fs::rename(&tmp, &target)
}

/// The request waiting for the server, if any. An unparsable file still counts
/// (as a non-forced request at time 0): its presence is the request.
pub fn pending_request(data_dir: &Path) -> Option<RenewRequest> {
	let bytes = std::fs::read(file(data_dir, REQUEST_FILE)).ok()?;
	Some(serde_json::from_slice(&bytes).unwrap_or(RenewRequest {
		force: false,
		requested_at: 0,
	}))
}

/// The reason the last attempt at a requested renewal failed, if it did.
pub fn last_error(data_dir: &Path) -> Option<String> {
	std::fs::read_to_string(file(data_dir, ERROR_FILE))
		.ok()
		.map(|text| text.trim().to_string())
}

/// Obtains and installs one certificate. The production implementation talks
/// to the CA; tests substitute a recorder.
pub trait Issuer: Send + Sync {
	/// Run one issuance end to end.
	fn issue(&self) -> Pin<Box<dyn Future<Output = Result<(), AcmeError>> + Send + '_>>;
}

/// When each kind of failed attempt may be retried (epoch seconds).
#[derive(Debug, Default)]
pub struct Backoff {
	scheduled: u64,
	requested: u64,
}

/// What one pass of the renewal loop did.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
	/// Nothing was due and nothing was asked for.
	Idle,
	/// A certificate was issued.
	Issued,
	/// The operator asked without `--force` and the certificate is not due.
	NotDue,
	/// Issuance failed with this message; the request, if any, is kept.
	Failed(String),
}

/// One pass: serve the operator's request, else renew when the certificate is
/// inside its window.
pub async fn cycle(
	issuer: &dyn Issuer,
	data_dir: &Path,
	renew_before_days: u64,
	now: u64,
	backoff: &mut Backoff,
) -> Outcome {
	let request = pending_request(data_dir);
	let due = needs_renewal(data_dir, renew_before_days, now);
	let wanted = request.as_ref().is_some_and(|r| r.force) || due;
	if request.is_some() && !wanted {
		let _ = std::fs::remove_file(file(data_dir, REQUEST_FILE));
		tracing::info!("requested renewal dropped: certificate is not inside its renewal window");
		return Outcome::NotDue;
	}
	let retry_at = if request.is_some() {
		backoff.requested
	} else {
		backoff.scheduled
	};
	if !wanted || now < retry_at {
		return Outcome::Idle;
	}
	match issuer.issue().await {
		Ok(()) => {
			*backoff = Backoff::default();
			let _ = std::fs::remove_file(file(data_dir, REQUEST_FILE));
			let _ = std::fs::remove_file(file(data_dir, ERROR_FILE));
			Outcome::Issued
		}
		Err(error) => {
			let message = error.to_string();
			if request.is_some() {
				backoff.requested = now.saturating_add(REQUEST_RETRY);
				let _ = std::fs::write(file(data_dir, ERROR_FILE), format!("{now} {message}\n"));
			} else {
				backoff.scheduled = now.saturating_add(SCHEDULED_RETRY);
			}
			Outcome::Failed(message)
		}
	}
}
