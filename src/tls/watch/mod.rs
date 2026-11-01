//! Picking up an operator's own certificate when its files change.
//!
//! Without `[acme]` the `[tls]` pair is the operator's: certbot, a
//! Cloudflare origin certificate or a hand-made one, replaced on disk when
//! it is renewed. [`CertWatcher`] compares the files' stamps, loads a
//! changed pair, checks that the chain parses and that the key belongs to
//! the certificate, and only then swaps it into the shared
//! [`ReloadableAcceptor`] every listener resolves through. A pair that does
//! not load, half written or mismatched, is refused and the certificate in
//! service stays.

use std::time::Duration;

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

use super::https::{Stamp, stamp};
use super::{EndPoint, ReloadableAcceptor, TlsError, end_point_of};
use crate::config::Tls;

/// How often the files are looked at.
pub const WATCH_INTERVAL: Duration = Duration::from_secs(60);

/// Watches the `[tls]` certificate and key files.
pub struct CertWatcher {
	tls: Tls,
	reloadable: ReloadableAcceptor,
	end_point: Option<EndPoint>,
	/// The chain (PEM) of the pair in service: the one that passed
	/// validation, which is not always the one on disk.
	served_chain: Option<String>,
	/// The stamps of the pair in service.
	loaded: Option<(Stamp, Stamp)>,
	/// The stamps of the last pair refused, so it is reported once.
	refused: Option<(Stamp, Stamp)>,
}

/// What one look at the files found.
#[derive(Debug, PartialEq, Eq)]
pub enum Polled {
	/// The files are the ones in service, or a pair already refused.
	Unchanged,
	/// A new pair was validated and is now in service; carries its chain.
	Reloaded {
		/// The certificate chain (PEM) now presented.
		chain_pem: String,
	},
	/// The files changed but do not form a usable pair; the certificate in
	/// service stays. Carries the reason.
	Refused(String),
}

impl CertWatcher {
	/// Watch `tls`, whose pair `reloadable` presents now.
	pub fn new(tls: Tls, reloadable: ReloadableAcceptor) -> Self {
		let loaded = stamps(&tls).ok();
		let served_chain = load_pair(&tls).ok().map(|pair| pair.chain_pem);
		CertWatcher {
			served_chain,
			tls,
			reloadable,
			end_point: None,
			loaded,
			refused: None,
		}
	}

	/// Also keep this channel binding in step with the certificate.
	pub fn with_end_point(mut self, end_point: EndPoint) -> Self {
		self.end_point = Some(end_point);
		self
	}

	/// The chain (PEM) of the certificate in service, `None` when the pair
	/// at start did not load. A pair on disk that was refused is not it.
	pub fn served_chain(&self) -> Option<&str> {
		self.served_chain.as_deref()
	}

	/// Look at the files once: swap a changed, valid pair in, refuse a
	/// changed pair that does not load.
	pub fn poll(&mut self) -> Polled {
		let current = match stamps(&self.tls) {
			Ok(current) => current,
			Err(error) => {
				return Polled::Refused(format!("cannot read the certificate files: {error}"));
			}
		};
		if self.loaded.as_ref() == Some(&current) || self.refused.as_ref() == Some(&current) {
			return Polled::Unchanged;
		}
		match load_pair(&self.tls) {
			Ok(pair) => {
				self.reloadable.reload(pair.acceptor);
				if let Some(end_point) = &self.end_point {
					end_point.set(end_point_of(&pair.leaf));
				}
				self.loaded = Some(current);
				self.refused = None;
				self.served_chain = Some(pair.chain_pem.clone());
				Polled::Reloaded {
					chain_pem: pair.chain_pem,
				}
			}
			Err(error) => {
				self.refused = Some(current);
				Polled::Refused(error.to_string())
			}
		}
	}
}

/// Look at the files every [`WATCH_INTERVAL`] for the life of the server.
/// A reloaded certificate gets its TLSA record republished through
/// `provider`, or a warning with the value to publish by hand. A
/// publication the provider refused is kept in `data_dir` and retried on
/// the ticks that follow, whether or not the files changed again; a refused
/// pair is logged once and the certificate in service stays.
pub async fn run(
	mut watcher: CertWatcher,
	provider: Option<std::sync::Arc<dyn crate::dns::provider::DnsProvider>>,
	hostname: String,
	data_dir: std::path::PathBuf,
) {
	// The chain in service, whose TLSA value is the one a reload replaces.
	let mut previous = watcher.served_chain().map(str::to_string);
	let mut ticker = tokio::time::interval(WATCH_INTERVAL);
	// The first tick is immediate and the files were just loaded.
	ticker.tick().await;
	loop {
		ticker.tick().await;
		let target = crate::dns::tlsa::Target {
			provider: provider.as_deref(),
			hostname: &hostname,
			data_dir: &data_dir,
		};
		match watcher.poll() {
			Polled::Unchanged => {
				if let Some(chain) = watcher.served_chain()
					&& let Some(outcome) =
						crate::dns::tlsa::retry_due(&target, chain, epoch_secs()).await
				{
					crate::dns::tlsa::log_outcome(&outcome, &hostname);
				}
			}
			Polled::Reloaded { chain_pem } => {
				tracing::info!(
					"the [tls] certificate files changed; the new certificate is in service"
				);
				let outcome = crate::dns::tlsa::refresh(
					&target,
					&chain_pem,
					previous.as_deref(),
					epoch_secs(),
				)
				.await;
				previous = Some(chain_pem);
				crate::dns::tlsa::log_outcome(&outcome, &hostname);
			}
			Polled::Refused(reason) => tracing::warn!(
				%reason,
				"the [tls] certificate files changed but are not a usable pair; the previous certificate stays in service",
			),
		}
	}
}

fn epoch_secs() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|elapsed| elapsed.as_secs())
		.unwrap_or(0)
}

fn stamps(tls: &Tls) -> std::io::Result<(Stamp, Stamp)> {
	Ok((stamp(&tls.cert_file)?, stamp(&tls.key_file)?))
}

/// A pair that loaded: the acceptor presenting it, its chain as read and
/// its leaf (DER).
struct Pair {
	acceptor: tokio_rustls::TlsAcceptor,
	chain_pem: String,
	leaf: Vec<u8>,
}

/// Read the pair once and validate it: every certificate of the chain
/// parses as X.509, and rustls accepts the key for the leaf (it refuses a
/// key that does not match). The bytes validated are the bytes returned,
/// so the TLSA record is computed from the certificate that is served.
fn load_pair(tls: &Tls) -> Result<Pair, TlsError> {
	let read = |path: &std::path::Path| {
		std::fs::read(path).map_err(|source| TlsError::Read {
			path: path.display().to_string(),
			source,
		})
	};
	let (cert_bytes, key_bytes) = (read(&tls.cert_file)?, read(&tls.key_file)?);
	let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert_bytes)
		.collect::<Result<_, _>>()
		.map_err(|error| TlsError::Invalid(error.to_string()))?;
	let leaf = certs
		.first()
		.ok_or_else(|| TlsError::NoCertificates(tls.cert_file.display().to_string()))?
		.as_ref()
		.to_vec();
	for cert in &certs {
		use x509_parser::prelude::FromDer;
		x509_parser::certificate::X509Certificate::from_der(cert.as_ref()).map_err(|_| {
			TlsError::Invalid("a certificate in the chain does not parse".to_string())
		})?;
	}
	let key = PrivateKeyDer::from_pem_slice(&key_bytes)
		.map_err(|_| TlsError::NoPrivateKey(tls.key_file.display().to_string()))?;
	super::ensure_crypto_provider();
	let config = super::server_config(certs, key, tls.client_ca.as_deref())?;
	let chain_pem = String::from_utf8(cert_bytes)
		.map_err(|_| TlsError::Invalid("the certificate file is not text".to_string()))?;
	Ok(Pair {
		acceptor: tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config)),
		chain_pem,
		leaf,
	})
}

#[cfg(test)]
mod tests;
