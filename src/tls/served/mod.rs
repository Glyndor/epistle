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

use super::usable_pair;

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
///
/// With `[acme]` on and no usable pair at the ACME path, the pair in service
/// is the bootstrap: the one the `[tls]` section names (what `init` writes,
/// `<data_dir>/keys/`) when it loads, or the one under `<data_dir>/keys/` when
/// the section still names the ACME path (an install made before the layout
/// changed, whose ACME pair was moved away). The server comes up that way and
/// asks the authority for a certificate instead of exiting for want of one. A
/// configuration that names no certificate at all keeps failing closed:
/// `None`.
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
		// The authority has not answered yet, or its pair is not
		// usable. The bootstrap is what the listeners present until
		// the ACME pair lands; the renewal loop replaces it in memory
		// and on the next start.
		let bootstrap = config
			.tls
			.as_ref()
			.filter(|tls| usable_pair(&tls.cert_file, &tls.key_file))
			.cloned()
			.or_else(|| {
				let cert_file = config.data_dir.join("keys").join("cert.pem");
				let key_file = config.data_dir.join("keys").join("key.pem");
				usable_pair(&cert_file, &key_file).then(|| Tls {
					cert_file,
					key_file,
					client_ca: client_ca.clone(),
				})
			});
		if let Some(bootstrap) = bootstrap {
			tracing::warn!(
				path = %bootstrap.cert_file.display(),
				"no usable certificate at the ACME path; the bootstrap pair is in service until \
				 the authority issues one"
			);
			return Some(ServedTls {
				tls: bootstrap,
				source: CertSource::Static,
			});
		}
	}
	config.tls.clone().map(|tls| ServedTls {
		tls,
		source: CertSource::Static,
	})
}

#[cfg(test)]
mod tests;
