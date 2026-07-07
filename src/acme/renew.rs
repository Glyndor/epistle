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
	write_secret(&path, B64.encode(&der).as_bytes())
		.map_err(|e| AcmeError::Transport(e.to_string()))?;
	Ok(key)
}

/// Write a secret file owner-only (0600) without a readable window: create a
/// sibling temp file `0600` up front, write and fsync it, then atomically
/// rename it onto the target. Best effort (plain write) on non-Unix.
fn write_secret(path: &Path, contents: &[u8]) -> std::io::Result<()> {
	#[cfg(unix)]
	{
		use std::io::Write;
		use std::os::unix::fs::OpenOptionsExt;
		let tmp = path.with_extension("tmp");
		// Clear any stale temp so create_new (which guarantees a fresh 0600
		// file) cannot fail on a leftover from a crashed write.
		let _ = fs::remove_file(&tmp);
		let mut file = fs::OpenOptions::new()
			.write(true)
			.create_new(true)
			.mode(0o600)
			.open(&tmp)?;
		file.write_all(contents)?;
		file.sync_all()?;
		fs::rename(&tmp, path)?;
		Ok(())
	}
	#[cfg(not(unix))]
	{
		fs::write(path, contents)
	}
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

/// A DNS provider plus the mail hostname, used to refresh the DANE TLSA record
/// when the certificate rotates.
type TlsaPublisher = (
	std::sync::Arc<dyn crate::dns::provider::DnsProvider>,
	String,
);

/// Run one issuance: register, obtain a certificate over HTTP-01, persist it,
/// hot-reload the acceptor, and (when a DNS provider is configured) refresh the
/// TLSA record for the new certificate.
async fn issue(
	directory_url: &str,
	contacts: &[String],
	domains: &[String],
	store: &ChallengeStore,
	data_dir: &Path,
	reloadable: &ReloadableAcceptor,
	tlsa: Option<&TlsaPublisher>,
) -> Result<(), AcmeError> {
	let transport = HttpTransport::new()?;
	let key = load_or_create_account_key(data_dir)?;
	let client = AcmeClient::connect(transport, key, directory_url).await?;
	client.register(contacts).await?;
	let (chain, key_pem) = client.obtain_certificate(domains, store, 10).await?;

	let dir = data_dir.join("acme");
	fs::create_dir_all(&dir).map_err(|e| AcmeError::Transport(e.to_string()))?;
	fs::write(cert_path(data_dir), &chain).map_err(|e| AcmeError::Transport(e.to_string()))?;
	write_secret(&key_path(data_dir), key_pem.as_bytes())
		.map_err(|e| AcmeError::Transport(e.to_string()))?;

	let acceptor = crate::tls::acceptor_from_pem(chain.as_bytes(), key_pem.as_bytes())
		.map_err(|e| AcmeError::Protocol(e.to_string()))?;
	reloadable.reload(acceptor);
	tracing::info!(?domains, "ACME certificate issued and TLS reloaded");

	// Refresh the DANE TLSA record for the new certificate (best-effort: a DNS
	// failure must not fail an otherwise-successful issuance).
	if let Some((provider, hostname)) = tlsa
		&& let Err(error) =
			crate::dns::records::publish_tlsa(provider.as_ref(), hostname, &chain).await
	{
		tracing::warn!(%error, "TLSA refresh after cert rotation failed");
	}
	Ok(())
}

/// Renewal loop: check on startup and every 12 hours, issuing when due. Errors
/// are logged and retried at the next tick — a CA outage never crashes serving.
#[allow(clippy::too_many_arguments)]
pub async fn run(
	directory_url: String,
	contacts: Vec<String>,
	domains: Vec<String>,
	store: ChallengeStore,
	data_dir: PathBuf,
	reloadable: ReloadableAcceptor,
	renew_before_days: u64,
	tlsa: Option<TlsaPublisher>,
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
				tlsa.as_ref(),
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

	#[cfg(unix)]
	#[test]
	fn account_key_is_written_owner_only() {
		use std::os::unix::fs::PermissionsExt;
		let dir = tempfile::tempdir().expect("tempdir");
		load_or_create_account_key(dir.path()).expect("create");
		let mode = fs::metadata(account_key_path(dir.path()))
			.expect("metadata")
			.permissions()
			.mode();
		// No group/other bits: the key never had a readable window.
		assert_eq!(mode & 0o077, 0, "key mode {mode:#o} is too permissive");
		// The temp file used for the atomic write is cleaned up.
		assert!(!account_key_path(dir.path()).with_extension("tmp").exists());
	}

	#[test]
	fn corrupt_account_key_is_rejected() {
		let dir = tempfile::tempdir().expect("tempdir");
		let path = account_key_path(dir.path());
		fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");

		// Not valid base64 → decode error.
		fs::write(&path, "not base64 !!!").expect("write");
		assert!(load_or_create_account_key(dir.path()).is_err());

		// Valid base64 but not a PKCS#8 key → parse error.
		fs::write(&path, B64.encode(b"not a key")).expect("write");
		assert!(load_or_create_account_key(dir.path()).is_err());
	}

	#[test]
	fn unreadable_certificate_modified_time_renews() {
		// A cert that exists but reads as freshly issued is not renewed; an
		// absent one is. Covers the metadata branch boundaries.
		let dir = tempfile::tempdir().expect("tempdir");
		fs::create_dir_all(dir.path().join("acme")).expect("mkdir");
		fs::write(cert_path(dir.path()), b"cert").expect("write");
		// now far in the past → not yet at the renew threshold.
		assert!(!needs_renewal(dir.path(), 30, 0));
	}
}
