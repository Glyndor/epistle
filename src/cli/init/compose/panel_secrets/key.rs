//! The panel's API key: one `panel` row in `api_keys.toml` and the file that
//! holds its secret.

use std::path::{Path, PathBuf};

use super::super::super::apply::{ApplyError, Report, ReportStep};
use super::held::{Held, trimmed};
use super::{KEY_LIFETIME_SECS, LABEL, RENEW_WITHIN_SECS, SCOPES};
use crate::api::{ApiKey, ApiKeyStore};

/// What happens to the API key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyAction {
	/// The file matches the stored key, which has time left.
	Reuse,
	/// No `panel` key exists, so one is created.
	Create,
	/// The file was lost or does not match the stored key, which has time
	/// left, so the secret is replaced and the expiry stays.
	Rotate,
	/// Fewer than 30 days remain, or the key has no expiry, so the secret and
	/// the expiry are both replaced.
	Renew,
}

impl std::fmt::Display for KeyAction {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str(match self {
			Self::Reuse => "reuse",
			Self::Create => "create",
			Self::Rotate => "replace the lost secret of",
			Self::Renew => "renew",
		})
	}
}

/// Where and when an action runs.
pub(super) struct Clock<'a> {
	/// The data directory holding `api_keys.toml`.
	pub(super) data_dir: &'a Path,
	/// Epoch seconds.
	pub(super) now: u64,
}

/// Decide from the stored row, the file and the time.
pub(super) fn decide(store: &ApiKeyStore, held: &Held, now: u64) -> Result<KeyAction, ApplyError> {
	let Some(row) = store.keys().iter().find(|key| key.label == LABEL) else {
		return Ok(KeyAction::Create);
	};
	check_shape(row)?;
	// An expiry at or before `now` saturates to zero, which is under the
	// threshold, so an expired key is renewed like one about to expire.
	let due = row
		.expires_at
		.is_none_or(|at| at.saturating_sub(now) < RENEW_WITHIN_SECS);
	let matches = matches!(held, Held::Present(bytes) if hash_matches(bytes, &row.hash));
	Ok(match (due, matches) {
		(true, _) => KeyAction::Renew,
		(false, true) => KeyAction::Reuse,
		(false, false) => KeyAction::Rotate,
	})
}

/// Refuse a `panel` key the operator made with another reach. Rotating its
/// secret would hand the panel whatever that key allows, `send` among it.
fn check_shape(row: &ApiKey) -> Result<(), ApplyError> {
	let mut scopes: Vec<&str> = row.scopes.iter().map(String::as_str).collect();
	scopes.sort_unstable();
	if scopes == SCOPES && row.domains.is_empty() && row.account.is_none() {
		return Ok(());
	}
	Err(ApplyError::PanelKey(format!(
		"an API key labelled \"{LABEL}\" exists with other settings than the panel's \
		 (scopes {:?}, domains {:?}, account {:?}); revoke it with `epistle api-key revoke \
		 {LABEL}` and rerun",
		row.scopes, row.domains, row.account
	)))
}

/// Whether the secret in `file` hashes to `stored`. The comparison runs in
/// constant time: the digest is public, but this is a credential check.
fn hash_matches(file: &[u8], stored: &str) -> bool {
	let Ok(text) = std::str::from_utf8(trimmed(file)) else {
		return false;
	};
	let digest = crate::api::api_keys::sha256_hash(text).to_ascii_lowercase();
	crate::util::constant_time::eq(digest.as_bytes(), stored.to_ascii_lowercase().as_bytes())
}

/// Carry out `action`. The file is written before the store changes, so a
/// failure between the two leaves a file the next run sees as not matching and
/// replaces, never a stored key whose secret is nowhere.
pub(super) fn apply(
	store: &mut ApiKeyStore,
	action: KeyAction,
	path: &Path,
	held: &Held,
	clock: &Clock<'_>,
	report: &mut Report,
) -> Result<(), ApplyError> {
	if action == KeyAction::Reuse {
		report.steps.push(ReportStep::Reused(path.to_path_buf()));
		return Ok(());
	}
	let secret = crate::cli::util::generate_secret()
		.ok_or_else(|| ApplyError::Rng("panel API key".to_string()))?;
	let hash = crate::api::api_keys::sha256_hash(&secret);
	write_token(path, &secret).map_err(|error| ApplyError::KeyWrite(path.to_path_buf(), error))?;
	let expires_at = clock.now + KEY_LIFETIME_SECS;
	let store_path: PathBuf = clock.data_dir.join("api_keys.toml");
	match action {
		KeyAction::Create => store.add(ApiKey {
			label: LABEL.to_string(),
			hash,
			expires_at: Some(expires_at),
			ip_cidr: None,
			scopes: SCOPES.iter().map(|scope| (*scope).to_string()).collect(),
			domains: Vec::new(),
			account: None,
		}),
		KeyAction::Rotate => store.rotate(LABEL, hash),
		KeyAction::Renew => store.renew(LABEL, hash, expires_at),
		KeyAction::Reuse => Ok(()),
	}
	.map_err(|error| ApplyError::KeyWrite(store_path, error))?;
	report.steps.push(match held {
		Held::Missing => ReportStep::Wrote(path.to_path_buf()),
		Held::Present(_) => ReportStep::Updated(path.to_path_buf()),
	});
	Ok(())
}

/// Write `secret` to the key file at `path`: owner-only, replaced in one
/// rename. Every writer of the file goes through here, so the file has one
/// mode and one shape whoever wrote it last.
pub(super) fn write_token(path: &Path, secret: &str) -> std::io::Result<()> {
	crate::storage::write_secret(path, secret.as_bytes())
}
