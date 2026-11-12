//! A certificate replaced while connections are open: sessions already
//! encrypted continue, and every handshake that has not happened yet gets the
//! new certificate, including one whose STARTTLS was already acknowledged.

use std::sync::Arc;

use epistle::smtp::server::{Server, TlsMode};
use epistle::smtp::sink::MemorySink;
use epistle::tls::{ReloadableAcceptor, acceptor_from_pem};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::{ClientConfig, RootCertStore, pki_types::ServerName};

use super::{support::*, wire};

struct Identity {
	acceptor: tokio_rustls::TlsAcceptor,
	root: tokio_rustls::rustls::pki_types::CertificateDer<'static>,
}

impl Identity {
	/// A client with no session cache, so a resumed session cannot stand in
	/// for the certificate check.
	fn connector(&self) -> TlsConnector {
		let mut roots = RootCertStore::empty();
		roots.add(self.root.clone()).expect("trust root");
		let config = ClientConfig::builder()
			.with_root_certificates(roots)
			.with_no_client_auth();
		TlsConnector::from(Arc::new(config))
	}
}

fn identity() -> Identity {
	epistle::tls::ensure_crypto_provider();
	let cert = rcgen::generate_simple_self_signed(vec!["mx.epistle.test".into()])
		.expect("test certificate");
	let acceptor = acceptor_from_pem(
		cert.cert.pem().as_bytes(),
		cert.signing_key.serialize_pem().as_bytes(),
	)
	.expect("TLS acceptor");
	Identity {
		acceptor,
		root: cert.cert.der().clone(),
	}
}

/// A connection whose STARTTLS was acknowledged and whose handshake is still
/// to be made.
async fn pending(listener: &Listener) -> TcpStream {
	let mut tcp = listener.connect().await;
	wire::send(&mut tcp, b"STARTTLS\r\n").await;
	wire::expect(&mut tcp, "220 ready to start TLS\r\n").await;
	tcp
}

async fn handshake(
	identity: &Identity,
	tcp: TcpStream,
) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
	let name = ServerName::try_from("mx.epistle.test").expect("server name");
	tokio::time::timeout(DEADLINE, identity.connector().connect(name, tcp))
		.await
		.expect("handshake deadline")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replaced_certificate_reaches_every_handshake_not_yet_made() {
	seed("certificate");
	let (old, new) = (identity(), identity());
	let acceptor = ReloadableAcceptor::new(old.acceptor.clone());
	let sink = Arc::new(MemorySink::new());
	let listener = Listener::start(
		Server::new("mx.epistle.test", sink.clone())
			.with_directory(directory())
			.with_tls(acceptor.clone(), TlsMode::Opportunistic),
	)
	.await;

	// Control: before the replacement the old certificate is the one trusted.
	let mut established = handshake(&old, pending(&listener).await)
		.await
		.expect("old certificate verifies before the replacement");
	wire::ehlo(&mut established).await;
	assert!(
		handshake(&new, pending(&listener).await).await.is_err(),
		"seed={SEED:#x} the new certificate must not verify before the replacement"
	);

	// Two handshakes held between STARTTLS and ClientHello across the swap.
	let held_new = pending(&listener).await;
	let held_old = pending(&listener).await;
	acceptor.reload(new.acceptor.clone());

	assert!(
		handshake(&old, held_old).await.is_err(),
		"seed={SEED:#x} a handshake held across the replacement still presented the old certificate"
	);
	let mut fresh = handshake(&new, held_new)
		.await
		.expect("a held handshake gets the new certificate");
	wire::ehlo(&mut fresh).await;
	let mut later = handshake(&new, pending(&listener).await)
		.await
		.expect("a connection opened after the replacement gets the new certificate");
	wire::ehlo(&mut later).await;

	// The session encrypted under the old certificate carries on and delivers.
	data(&mut established, false).await;
	wire::send(&mut established, &message(7, 4, false)).await;
	wire::send(&mut established, b".\r\n").await;
	wire::expect(&mut established, wire::OK).await;
	let stored = inventory(
		sink.messages().into_iter().map(|m| m.data).collect(),
		4,
		false,
	);
	assert_eq!(
		stored,
		std::collections::BTreeMap::from([(7, 1)]),
		"seed={SEED:#x} the session open across the replacement delivered once"
	);
}
