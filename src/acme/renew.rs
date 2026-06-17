//! ACME renewal: persist the account key and issued certificate, decide when
//! to renew, and hot-reload the TLS acceptor with a fresh certificate.
//!
//! This is the I/O glue tying the (unit-tested) ACME client, the HTTP-01
//! responder, certificate persistence and the reloadable acceptor together; it
//! is excluded from the no-network coverage gate. The pure decision
//! (`needs_renewal`) and key persistence are tested.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

use super::client::{AcmeClient, AcmeError};
use super::http01::ChallengeStore;
use super::jws::AccountKey;
use super::transport::HttpTransport;
use crate::tls::ReloadableAcceptor;

/// Assumed certificate lifetime (Let's Encrypt issues 90-day certs).
const LIFETIME_DAYS: u64 = 90;
/// How often the loop wakes to check for renewal.
const CHECK_INTERVAL: Duration = Duration::from_secs(12 * 3600);

fn account_key_path(data_dir: &Path) -> PathBuf {
	data_dir.join("acme").join("account.key")
}
fn cert_path(data_dir: &Path) -> PathBuf {
	data_dir.join("acme").join("cert.pem")
}
fn key_path(data_dir: &Path) -> PathBuf {
	data_dir.join("acme").join("key.pem")
}

/// Load the persisted account key, or generate and persist a new one.
pub fn load_or_create_account_key(data_dir: &Path) -> Result<AccountKey, AcmeError> {
	let path = account_key_path(data_dir);
	if let Ok(encoded) = fs::read_to_string(&path) {
		let der = B64
			.decode(encoded.trim())
			.map_err(|e| AcmeError::Protocol(format!("account key: {e}")))?;
		return AccountKey::from_pkcs8(&der).map_err(|e| AcmeError::Protocol(e.to_string()));
	}
	let (key, der) = AccountKey::generate().map_err(|e| AcmeError::Protocol(e.to_string()))?;
	if let Some(parent) = path.parent() {
		fs::create_dir_all(parent).map_err(|e| AcmeError::Transport(e.to_string()))?;
	}
	fs::write(&path, B64.encode(&der)).map_err(|e| AcmeError::Transport(e.to_string()))?;
	restrict(&path);
	Ok(key)
}

/// Restrict a secret file to owner-only (0600) on Unix; best effort elsewhere.
fn restrict(path: &Path) {
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
	}
	#[cfg(not(unix))]
	let _ = path;
}

/// Whether a certificate should be (re)issued now: absent, unreadable, or
/// within `renew_before_days` of its assumed expiry.
pub fn needs_renewal(data_dir: &Path, renew_before_days: u64, now_secs: u64) -> bool {
	let Ok(meta) = fs::metadata(cert_path(data_dir)) else {
		return true;
	};
	let Ok(modified) = meta.modified() else {
		return true;
	};
	let issued = modified
		.duration_since(UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	let renew_at = issued + LIFETIME_DAYS.saturating_sub(renew_before_days) * 86_400;
	now_secs >= renew_at
}

fn now_secs() -> u64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0)
}

/// Run one issuance: register, obtain a certificate over HTTP-01, persist it,
/// and hot-reload the acceptor.
async fn issue(
	directory_url: &str,
	contacts: &[String],
	domains: &[String],
	store: &ChallengeStore,
	data_dir: &Path,
	reloadable: &ReloadableAcceptor,
) -> Result<(), AcmeError> {
	let transport = HttpTransport::new()?;
	let key = load_or_create_account_key(data_dir)?;
	let client = AcmeClient::connect(transport, key, directory_url).await?;
	client.register(contacts).await?;
	let (chain, key_pem) = client.obtain_certificate(domains, store, 10).await?;

	let dir = data_dir.join("acme");
	fs::create_dir_all(&dir).map_err(|e| AcmeError::Transport(e.to_string()))?;
	fs::write(cert_path(data_dir), &chain).map_err(|e| AcmeError::Transport(e.to_string()))?;
	fs::write(key_path(data_dir), &key_pem).map_err(|e| AcmeError::Transport(e.to_string()))?;
	restrict(&key_path(data_dir));

	let acceptor = crate::tls::acceptor_from_pem(chain.as_bytes(), key_pem.as_bytes())
		.map_err(|e| AcmeError::Protocol(e.to_string()))?;
	reloadable.reload(acceptor);
	tracing::info!(?domains, "ACME certificate issued and TLS reloaded");
	Ok(())
}

/// Renewal loop: check on startup and every 12 hours, issuing when due. Errors
/// are logged and retried at the next tick — a CA outage never crashes serving.
pub async fn run(
	directory_url: String,
	contacts: Vec<String>,
	domains: Vec<String>,
	store: ChallengeStore,
	data_dir: PathBuf,
	reloadable: ReloadableAcceptor,
	renew_before_days: u64,
) {
	loop {
		if needs_renewal(&data_dir, renew_before_days, now_secs())
			&& let Err(error) = issue(
				&directory_url,
				&contacts,
				&domains,
				&store,
				&data_dir,
				&reloadable,
			)
			.await
		{
			tracing::warn!(%error, "ACME renewal failed; will retry");
		}
		tokio::time::sleep(CHECK_INTERVAL).await;
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn needs_renewal_when_certificate_absent() {
		let dir = tempfile::tempdir().expect("tempdir");
		assert!(needs_renewal(dir.path(), 30, now_secs()));
	}

	#[test]
	fn fresh_certificate_does_not_need_renewal() {
		let dir = tempfile::tempdir().expect("tempdir");
		fs::create_dir_all(dir.path().join("acme")).expect("mkdir");
		fs::write(cert_path(dir.path()), b"cert").expect("write");
		// Just written → far from the 90-day expiry.
		assert!(!needs_renewal(dir.path(), 30, now_secs()));
	}

	#[test]
	fn old_certificate_needs_renewal() {
		let dir = tempfile::tempdir().expect("tempdir");
		fs::create_dir_all(dir.path().join("acme")).expect("mkdir");
		fs::write(cert_path(dir.path()), b"cert").expect("write");
		// 89 days in the future is within the 30-day renewal window.
		let future = now_secs() + 89 * 86_400;
		assert!(needs_renewal(dir.path(), 30, future));
	}

	#[test]
	fn account_key_persists_and_reloads() {
		let dir = tempfile::tempdir().expect("tempdir");
		let a = load_or_create_account_key(dir.path()).expect("create");
		let b = load_or_create_account_key(dir.path()).expect("reload");
		// Reload returns the same key (same JWK), not a new one.
		assert_eq!(a.jwk(), b.jwk());
	}
}
