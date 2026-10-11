//! The one answer to "which certificate does this server present".
//!
//! `serve` loads its certificate once at start while ACME renewal writes
//! `<data_dir>/acme/{cert,key}.pem` and only hot-reloads in memory. A
//! hand-written config can point `[tls] cert_file` somewhere else, so reading
//! `[tls]` alone serves the bootstrap pair again after every restart until the
//! next renewal. `serve`, `probe` and `tls show` all resolve through
//! [`served_tls`], so they cannot disagree.

use std::path::PathBuf;

use crate::config::{Config, Tls};

/// Where the presented certificate comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertSource {
	/// The pair ACME issued under `<data_dir>/acme`.
	Acme,
	/// The `[tls]` pair written by hand or by `init`.
	Static,
}

impl CertSource {
	/// Lowercase name used in command output.
	pub fn as_str(self) -> &'static str {
		match self {
			CertSource::Acme => "acme",
			CertSource::Static => "static",
		}
	}
}

/// The certificate and key `serve` must present, plus where they came from.
#[derive(Debug, Clone)]
pub struct ServedTls {
	/// Pair to load. `client_ca` is always carried over from `[tls]`.
	pub tls: Tls,
	/// Which of the two sources won.
	pub source: CertSource,
}

/// The pair `serve` presents: the ACME pair when `[acme]` is set and
/// `<data_dir>/acme/{cert,key}.pem` exists and forms a usable pair, otherwise
/// `[tls]`. `None` when neither exists.
pub fn served_tls(config: &Config) -> Option<ServedTls> {
	let client_ca = config.tls.as_ref().and_then(|tls| tls.client_ca.clone());
	if config.acme.is_some() {
		let cert_file: PathBuf = crate::acme::renew::cert_path(&config.data_dir);
		let key_file: PathBuf = crate::acme::renew::key_path(&config.data_dir);
		if usable_pair(&cert_file, &key_file) {
			return Some(ServedTls {
				tls: Tls {
					cert_file,
					key_file,
					client_ca,
				},
				source: CertSource::Acme,
			});
		}
	}
	config.tls.clone().map(|tls| ServedTls {
		tls,
		source: CertSource::Static,
	})
}

/// Whether both files load and rustls accepts the key for the certificate.
fn usable_pair(cert_file: &std::path::Path, key_file: &std::path::Path) -> bool {
	super::ensure_crypto_provider();
	let (Ok(certs), Ok(key)) = (super::load_certs(cert_file), super::load_key(key_file)) else {
		return false;
	};
	super::server_config(certs, key, None).is_ok()
}

#[cfg(test)]
#[path = "served_tests.rs"]
mod tests;
