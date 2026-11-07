use std::sync::Arc;

use super::transport::Stream;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::{TlsConnector, client::TlsStream};

pub type TlsClient = TlsStream<Stream>;

pub struct Certificate {
	pub tls: crate::config::Tls,
	connector: TlsConnector,
	_dir: tempfile::TempDir,
}

impl Certificate {
	pub fn new() -> Self {
		crate::tls::ensure_crypto_provider();
		let dir = tempfile::tempdir().expect("TLS fixture");
		let certified =
			rcgen::generate_simple_self_signed(vec!["mail.example.org".into()]).expect("cert");
		let tls = crate::config::Tls {
			cert_file: dir.path().join("cert.pem"),
			key_file: dir.path().join("key.pem"),
			client_ca: None,
		};
		std::fs::write(&tls.cert_file, certified.cert.pem()).expect("cert file");
		std::fs::write(&tls.key_file, certified.signing_key.serialize_pem()).expect("key file");
		let mut roots = RootCertStore::empty();
		roots.add(certified.cert.der().clone()).expect("trust");
		let config = ClientConfig::builder()
			.with_root_certificates(roots)
			.with_no_client_auth();
		Self {
			tls,
			connector: TlsConnector::from(Arc::new(config)),
			_dir: dir,
		}
	}

	pub async fn connect(&self, stream: Stream) -> TlsClient {
		tokio::time::timeout(
			super::DEADLINE,
			self.connector
				.connect("mail.example.org".try_into().expect("SNI"), stream),
		)
		.await
		.expect("TLS deadline")
		.expect("TLS handshake")
	}
}
