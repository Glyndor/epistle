//! TLS configuration and certificate refresh for the public HTTPS listener.

use std::fs;
use std::sync::Arc;
use std::time::SystemTime;

use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::{ServerConfig, SupportedProtocolVersion};

use super::{ReloadableAcceptor, TlsError};
use crate::config::Tls;

const VERSIONS: &[&SupportedProtocolVersion] = super::PROTOCOL_VERSIONS;

fn acceptor(config: &Tls) -> Result<TlsAcceptor, TlsError> {
	super::ensure_crypto_provider();
	let mut server = ServerConfig::builder_with_protocol_versions(VERSIONS)
		.with_no_client_auth()
		.with_single_cert(
			super::load_certs(&config.cert_file)?,
			super::load_key(&config.key_file)?,
		)
		.map_err(|error| TlsError::Invalid(error.to_string()))?;
	server.alpn_protocols = vec![b"http/1.1".to_vec()];
	Ok(TlsAcceptor::from(Arc::new(server)))
}

/// What identifies one version of a file: its modification time, length
/// and (on Unix) inode, so a rename over it counts as a change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Stamp {
	modified: SystemTime,
	length: u64,
	#[cfg(unix)]
	inode: u64,
}

pub(super) fn stamp(path: &std::path::Path) -> std::io::Result<Stamp> {
	let metadata = fs::metadata(path)?;
	Ok(Stamp {
		modified: metadata.modified()?,
		length: metadata.len(),
		#[cfg(unix)]
		inode: {
			use std::os::unix::fs::MetadataExt;
			metadata.ino()
		},
	})
}

pub(crate) struct FileAcceptor {
	config: Tls,
	loaded: Option<(Stamp, Stamp)>,
	acceptor: ReloadableAcceptor,
}

impl FileAcceptor {
	pub(crate) fn new(config: Tls) -> Result<Self, TlsError> {
		let loaded = Self::stamps(&config).ok();
		let acceptor = ReloadableAcceptor::new(acceptor(&config)?);
		Ok(Self {
			config,
			loaded,
			acceptor,
		})
	}

	fn stamps(config: &Tls) -> std::io::Result<(Stamp, Stamp)> {
		Ok((stamp(&config.cert_file)?, stamp(&config.key_file)?))
	}

	pub(crate) fn current(&mut self) -> TlsAcceptor {
		match Self::stamps(&self.config) {
			Ok(stamps) if self.loaded.as_ref() != Some(&stamps) => match acceptor(&self.config) {
				Ok(fresh) => {
					self.acceptor.reload(fresh);
					self.loaded = Some(stamps);
				}
				Err(error) => tracing::warn!(%error, "cannot reload MTA-STS certificate"),
			},
			Err(error) => tracing::warn!(%error, "cannot stat MTA-STS certificate files"),
			_ => {}
		}
		self.acceptor.current()
	}
}

#[cfg(test)]
mod tests;
