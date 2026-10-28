//! ACME renewal: persist the account key and issued certificate, decide when
//! to renew, and hot-reload the TLS acceptor with a fresh certificate.
//!
//! This is the I/O glue tying the (unit-tested) ACME client, the challenge
//! responder, certificate persistence and the reloadable acceptor together; it
//! is excluded from the no-network coverage gate. The pure decision
//! (`needs_renewal`) and key persistence are tested.

use std::fs;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

use super::challenge::ChallengeResponder;
use super::client::{AcmeClient, AcmeError};
use super::jws::AccountKey;
use super::renew_request::{Backoff, Issuer, Outcome, cycle};
use super::transport::HttpTransport;
use crate::tls::ReloadableAcceptor;

/// Assumed certificate lifetime (Let's Encrypt issues 90-day certs).
const LIFETIME_DAYS: u64 = 90;
/// How often the loop wakes: often enough to serve an operator's renewal
/// request promptly; scheduled failures back off for much longer.
const CHECK_INTERVAL: Duration = Duration::from_secs(60);

fn account_key_path(data_dir: &Path) -> PathBuf {
	data_dir.join("acme").join("account.key")
}
pub(crate) fn cert_path(data_dir: &Path) -> PathBuf {
	data_dir.join("acme").join("cert.pem")
}
pub(crate) fn key_path(data_dir: &Path) -> PathBuf {
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

/// What the certificate at the ACME path is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CertificateState {
	/// No file on disk.
	Missing,
	/// The file is there but could not be read or parsed.
	Unreadable,
	/// A certificate an authority issued, with the second its
	/// validity ends.
	Issued(u64),
	/// A certificate that is its own issuer: nobody vouches for it.
	SelfIssued,
}

/// Whether a certificate should be (re)issued now: absent, unreadable,
/// self-issued, or within `renew_before_days` of its X.509 expiry.
///
/// A self-issued certificate is due however far its expiry is: no
/// authority issues one, so it is a placeholder (the self-signed pair
/// `init` used to write at the ACME path) and the only way to have a
/// certificate the authority vouches for is to ask for one. If
/// parsing fails, assume a 90-day lifetime from the file modification
/// time.
pub fn needs_renewal(data_dir: &Path, renew_before_days: u64, now_secs: u64) -> bool {
	let path = cert_path(data_dir);
	match certificate_state(&path) {
		CertificateState::Missing => true,
		CertificateState::SelfIssued => true,
		CertificateState::Issued(expires) => {
			let window = renew_before_days.saturating_mul(86_400);
			now_secs >= expires.saturating_sub(window)
		}
		CertificateState::Unreadable => {
			let Ok(meta) = fs::metadata(&path) else {
				return true;
			};
			let Ok(modified) = meta.modified() else {
				return true;
			};
			let issued = modified
				.duration_since(UNIX_EPOCH)
				.map(|d| d.as_secs())
				.unwrap_or(0);
			let renew_at = issued.saturating_add(
				LIFETIME_DAYS
					.saturating_sub(renew_before_days)
					.saturating_mul(86_400),
			);
			now_secs >= renew_at
		}
	}
}

/// Read the certificate at the ACME path and say what it is.
fn certificate_state(path: &Path) -> CertificateState {
	use rustls_pki_types::CertificateDer;
	use rustls_pki_types::pem::PemObject;
	use x509_parser::prelude::FromDer;

	// The leaf is first in the persisted ACME certificate chain.
	let Ok(der) = CertificateDer::from_pem_file(path) else {
		return if path.exists() {
			CertificateState::Unreadable
		} else {
			CertificateState::Missing
		};
	};
	let Ok((_, cert)) = x509_parser::certificate::X509Certificate::from_der(der.as_ref()) else {
		return CertificateState::Unreadable;
	};
	// The issuer is the subject: the certificate signed itself.
	// A certificate an authority issued names that authority as its
	// issuer, so the two differ.
	if cert.issuer().as_raw() == cert.subject().as_raw() {
		return CertificateState::SelfIssued;
	}
	CertificateState::Issued(u64::try_from(cert.validity().not_after.timestamp()).unwrap_or(0))
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

/// Run one issuance: register, obtain a certificate through the configured
/// challenge, persist it,
/// hot-reload the acceptor, and (when a DNS provider is configured) refresh the
/// TLSA record for the new certificate.
async fn issue(
	directory_url: &str,
	contacts: &[String],
	domains: &[String],
	responder: &dyn ChallengeResponder,
	data_dir: &Path,
	reloadable: &ReloadableAcceptor,
	tlsa: Option<&TlsaPublisher>,
) -> Result<(), AcmeError> {
	let transport = HttpTransport::new()?;
	let key = load_or_create_account_key(data_dir)?;
	let client = AcmeClient::connect(transport, key, directory_url).await?;
	client.register(contacts).await?;
	let (chain, key_pem) = client.obtain_certificate(domains, responder, 10).await?;

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

/// The production [`Issuer`]: one ACME order, then install the result.
struct AcmeIssuer {
	directory_url: String,
	contacts: Vec<String>,
	domains: Vec<String>,
	responder: std::sync::Arc<dyn ChallengeResponder>,
	data_dir: PathBuf,
	reloadable: ReloadableAcceptor,
	tlsa: Option<TlsaPublisher>,
}

impl Issuer for AcmeIssuer {
	fn issue(&self) -> Pin<Box<dyn Future<Output = Result<(), AcmeError>> + Send + '_>> {
		Box::pin(issue(
			&self.directory_url,
			&self.contacts,
			&self.domains,
			self.responder.as_ref(),
			&self.data_dir,
			&self.reloadable,
			self.tlsa.as_ref(),
		))
	}
}

/// Renewal loop: wakes every minute and either serves an operator's request or
/// issues when the certificate is inside its renewal window. Errors are logged
/// and retried after a back-off; a CA outage never crashes serving.
#[allow(clippy::too_many_arguments)]
pub async fn run(
	directory_url: String,
	contacts: Vec<String>,
	domains: Vec<String>,
	responder: std::sync::Arc<dyn ChallengeResponder>,
	data_dir: PathBuf,
	reloadable: ReloadableAcceptor,
	renew_before_days: u64,
	tlsa: Option<TlsaPublisher>,
) {
	let issuer = AcmeIssuer {
		directory_url,
		contacts,
		domains,
		responder,
		data_dir: data_dir.clone(),
		reloadable,
		tlsa,
	};
	let mut backoff = Backoff::default();
	loop {
		if let Outcome::Failed(error) = cycle(
			&issuer,
			&data_dir,
			renew_before_days,
			now_secs(),
			&mut backoff,
		)
		.await
		{
			tracing::warn!(%error, "ACME renewal failed; will retry");
		}
		tokio::time::sleep(CHECK_INTERVAL).await;
	}
}

#[cfg(test)]
mod tests;
