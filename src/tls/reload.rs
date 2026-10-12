//! Shared certificate resolution for listener acceptor clones.

use std::sync::{Arc, RwLock};

use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::server::{ClientHello, ResolvesServerCert};
use tokio_rustls::rustls::sign::CertifiedKey;
use tokio_rustls::rustls::{ServerConfig, version};

#[derive(Debug)]
struct Resolver {
	current: RwLock<Arc<dyn ResolvesServerCert>>,
}

impl ResolvesServerCert for Resolver {
	fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
		let resolver = self.current.read().expect("TLS resolver lock").clone();
		resolver.resolve(hello)
	}

	fn only_raw_public_keys(&self) -> bool {
		self.current
			.read()
			.expect("TLS resolver lock")
			.only_raw_public_keys()
	}
}

/// A shared, reloadable certificate source. Every clone of the current
/// acceptor resolves the latest certificate at handshake time, including
/// acceptors retained by listeners before renewal. Established connections
/// keep their negotiated TLS state.
#[derive(Clone)]
pub struct ReloadableAcceptor {
	acceptor: TlsAcceptor,
	resolver: Arc<Resolver>,
}

impl ReloadableAcceptor {
	/// Wrap an initial acceptor, preserving its TLS and client-auth policies.
	pub fn new(acceptor: TlsAcceptor) -> Self {
		let mut config = (**acceptor.config()).clone();
		let resolver = Arc::new(Resolver {
			current: RwLock::new(config.cert_resolver.clone()),
		});
		config.cert_resolver = resolver.clone();
		Self {
			acceptor: TlsAcceptor::from(Arc::new(config)),
			resolver,
		}
	}

	/// Like [`ReloadableAcceptor::new`], and also answer TLS-ALPN-01
	/// (RFC 8737): a handshake offering `acme-tls/1` gets the challenge
	/// certificate `store` holds for its SNI name, or fails when no order is
	/// pending for it. Every other handshake resolves the current certificate
	/// as before.
	pub fn with_acme_alpn(
		acceptor: TlsAcceptor,
		store: Arc<crate::acme::tlsalpn::AlpnChallengeStore>,
	) -> Self {
		let mut config = (**acceptor.config()).clone();
		let resolver = Arc::new(Resolver {
			current: RwLock::new(config.cert_resolver.clone()),
		});
		config.cert_resolver = Arc::new(crate::acme::tlsalpn::AlpnResolver::new(
			store,
			resolver.clone(),
		));
		config.alpn_protocols = crate::acme::tlsalpn::SERVED_ALPN_PROTOCOLS
			.iter()
			.map(|protocol| protocol.to_vec())
			.collect();
		Self {
			acceptor: TlsAcceptor::from(Arc::new(config)),
			resolver,
		}
	}

	/// Clone an acceptor that continues to observe certificate renewals.
	pub fn current(&self) -> TlsAcceptor {
		self.acceptor.clone()
	}

	/// Publish a newly issued certificate to all listener acceptor clones.
	/// TLS settings and client-auth policy remain those of the initial config.
	pub fn reload(&self, acceptor: TlsAcceptor) {
		*self.resolver.current.write().expect("TLS resolver lock") =
			acceptor.config().cert_resolver.clone();
	}

	/// An acceptor for an HTTPS listener that presents the same, renewing
	/// certificate. It differs from [`Self::current`] in two ways: it never
	/// asks for a client certificate (a browser would prompt the user for
	/// one), and it negotiates `http/1.1` over ALPN.
	pub fn https(&self) -> TlsAcceptor {
		super::ensure_crypto_provider();
		let mut config =
			ServerConfig::builder_with_protocol_versions(&[&version::TLS13, &version::TLS12])
				.with_no_client_auth()
				.with_cert_resolver(self.resolver.clone());
		config.alpn_protocols = vec![b"http/1.1".to_vec()];
		TlsAcceptor::from(Arc::new(config))
	}
}

#[cfg(test)]
#[path = "reload_tests_alpn.rs"]
mod tests_alpn;
