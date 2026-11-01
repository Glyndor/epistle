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
	write_atomic(path, contents, 0o600)
}

/// The same write with the file mode the caller names: the certificate chain
/// is public and keeps `0644`, the key keeps `0600`.
fn write_atomic(path: &Path, contents: &[u8], mode: u32) -> std::io::Result<()> {
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
			.mode(mode)
			.open(&tmp)?;
		file.write_all(contents)?;
		file.sync_all()?;
		fs::rename(&tmp, path)?;
		Ok(())
	}
	#[cfg(not(unix))]
	{
		let _ = mode;
		fs::write(path, contents)
	}
}

/// Whether the ACME pair is usable and what its leaf certificate is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CertificateState {
	/// The certificate or key cannot be loaded, parsed, or used together.
	Unusable,
	/// A certificate an authority issued, with the second its
	/// validity ends.
	Issued(u64),
	/// A certificate that is its own issuer: nobody vouches for it.
	SelfIssued,
}

/// Whether a certificate should be (re)issued now: an unusable ACME pair,
/// a self-issued certificate, or a certificate within `renew_before_days`
/// of its X.509 expiry.
///
/// Pair usability uses the same TLS check as the served certificate selection.
/// A self-issued certificate is due however far its expiry is: it is a
/// placeholder rather than a certificate issued by an authority.
pub fn needs_renewal(data_dir: &Path, renew_before_days: u64, now_secs: u64) -> bool {
	match certificate_state(&cert_path(data_dir), &key_path(data_dir)) {
		CertificateState::Unusable | CertificateState::SelfIssued => true,
		CertificateState::Issued(expires) => {
			let window = renew_before_days.saturating_mul(86_400);
			now_secs >= expires.saturating_sub(window)
		}
	}
}

/// Check the ACME pair and classify its leaf certificate.
fn certificate_state(path: &Path, key_path: &Path) -> CertificateState {
	use rustls_pki_types::CertificateDer;
	use rustls_pki_types::pem::PemObject;
	use x509_parser::prelude::FromDer;

	if !crate::tls::usable_pair(path, key_path) {
		return CertificateState::Unusable;
	}

	// The leaf is first in the persisted ACME certificate chain.
	let Ok(der) = CertificateDer::from_pem_file(path) else {
		return CertificateState::Unusable;
	};
	let Ok((_, cert)) = x509_parser::certificate::X509Certificate::from_der(der.as_ref()) else {
		return CertificateState::Unusable;
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

/// Put an issued pair in place. The pair is judged first, as a TLS acceptor
/// built from the bytes in memory: a chain the key does not belong to, or one
/// that does not parse, is refused while the files on disk and the acceptor
/// in use are still the previous good pair. Only then are the two files
/// replaced, each through a temporary file and a rename, and the acceptor
/// swapped.
fn install(
	data_dir: &Path,
	chain: &str,
	key_pem: &str,
	reloadable: &ReloadableAcceptor,
) -> Result<(), AcmeError> {
	let acceptor = crate::tls::acceptor_from_pem(chain.as_bytes(), key_pem.as_bytes())
		.map_err(|e| AcmeError::Protocol(e.to_string()))?;
	fs::create_dir_all(data_dir.join("acme")).map_err(|e| AcmeError::Transport(e.to_string()))?;
	write_atomic(&cert_path(data_dir), chain.as_bytes(), 0o644)
		.map_err(|e| AcmeError::Transport(e.to_string()))?;
	write_secret(&key_path(data_dir), key_pem.as_bytes())
		.map_err(|e| AcmeError::Transport(e.to_string()))?;
	reloadable.reload(acceptor);
	Ok(())
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
	responder: std::sync::Arc<dyn ChallengeResponder>,
	data_dir: &Path,
	reloadable: &ReloadableAcceptor,
	tlsa: Option<&TlsaPublisher>,
) -> Result<(), AcmeError> {
	let transport = HttpTransport::new()?;
	let key = load_or_create_account_key(data_dir)?;
	let client = AcmeClient::connect(transport, key, directory_url).await?;
	client.register(contacts).await?;
	let (chain, key_pem) = client.obtain_certificate(domains, responder, 10).await?;

	// The certificate being replaced: its TLSA value is one this server served.
	let previous = fs::read_to_string(cert_path(data_dir)).ok();
	install(data_dir, &chain, &key_pem, reloadable)?;
	tracing::info!(?domains, "ACME certificate issued and TLS reloaded");

	// Refresh the DANE TLSA record for the new certificate. A DNS failure must
	// not fail an otherwise-successful issuance, and it is not dropped either:
	// the publication is kept and the renewal loop retries it.
	if let Some((provider, hostname)) = tlsa {
		let target = crate::dns::tlsa::Target {
			provider: Some(provider.as_ref()),
			hostname,
			data_dir,
		};
		let outcome =
			crate::dns::tlsa::refresh(&target, &chain, previous.as_deref(), now_secs()).await;
		crate::dns::tlsa::log_outcome(&outcome, hostname);
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
			self.responder.clone(),
			&self.data_dir,
			&self.reloadable,
			self.tlsa.as_ref(),
		))
	}
}

/// Publish again a TLSA record whose last attempt failed, once its wait is
/// over, for the certificate in service.
async fn retry_tlsa(issuer: &AcmeIssuer) {
	let Some((provider, hostname)) = &issuer.tlsa else {
		return;
	};
	let target = crate::dns::tlsa::Target {
		provider: Some(provider.as_ref()),
		hostname,
		data_dir: &issuer.data_dir,
	};
	// Only a pair that works together is in service; anything else on disk
	// is not published.
	let (cert, key) = (cert_path(&issuer.data_dir), key_path(&issuer.data_dir));
	if !crate::tls::usable_pair(&cert, &key) {
		return;
	}
	let Ok(chain) = fs::read_to_string(&cert) else {
		return;
	};
	if let Some(outcome) = crate::dns::tlsa::retry_due(&target, &chain, now_secs()).await {
		crate::dns::tlsa::log_outcome(&outcome, hostname);
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
		retry_tlsa(&issuer).await;
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
