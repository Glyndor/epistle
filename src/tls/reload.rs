//! Shared certificate resolution for listener acceptor clones.

use std::sync::{Arc, RwLock};

use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::server::{ClientHello, ResolvesServerCert};
use tokio_rustls::rustls::sign::CertifiedKey;

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
}
