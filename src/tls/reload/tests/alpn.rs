//! TLS-ALPN-01 through the shared reloadable resolver: the challenge
//! certificate answers only `acme-tls/1` handshakes, and only while an order
//! is pending for the SNI name; every other handshake is unaffected.

use std::sync::Arc;

use tokio_rustls::rustls::client::danger::{
	HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use super::ReloadableAcceptor;
use crate::acme::tlsalpn::AlpnChallengeStore;

const HOST: &str = "mail.example.org";
const ACME_IDENTIFIER: &str = "1.3.6.1.5.5.7.1.31";

/// Accepts any certificate and handshake signature: these tests look at which
/// certificate the server chose. webpki's signature check would also parse
/// the certificate and refuse the critical `acmeIdentifier` extension that
/// only an ACME validator understands.
#[derive(Debug)]
struct AnyCert(Arc<tokio_rustls::rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for AnyCert {
	fn verify_server_cert(
		&self,
		_: &CertificateDer<'_>,
		_: &[CertificateDer<'_>],
		_: &ServerName<'_>,
		_: &[u8],
		_: UnixTime,
	) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
		Ok(ServerCertVerified::assertion())
	}
	fn verify_tls12_signature(
		&self,
		_: &[u8],
		_: &CertificateDer<'_>,
		_: &DigitallySignedStruct,
	) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
		Ok(HandshakeSignatureValid::assertion())
	}
	fn verify_tls13_signature(
		&self,
		_: &[u8],
		_: &CertificateDer<'_>,
		_: &DigitallySignedStruct,
	) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
		Ok(HandshakeSignatureValid::assertion())
	}
	fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
		self.0.signature_verification_algorithms.supported_schemes()
	}
}

/// The normal server certificate and an acceptor serving it.
fn normal_acceptor() -> (TlsAcceptor, Vec<u8>) {
	crate::tls::ensure_crypto_provider();
	let certified = rcgen::generate_simple_self_signed(vec![HOST.to_string()]).expect("cert");
	let leaf = certified.cert.der().clone();
	let key = PrivateKeyDer::try_from(certified.signing_key.serialize_der()).expect("key");
	let config = ServerConfig::builder()
		.with_no_client_auth()
		.with_single_cert(vec![leaf.clone()], key)
		.expect("server config");
	(TlsAcceptor::from(Arc::new(config)), leaf.to_vec())
}

/// What one handshake produced: the leaf the server presented and the ALPN
/// protocol it negotiated.
struct Handshake {
	leaf: Vec<u8>,
	alpn: Option<Vec<u8>>,
}

/// Handshake against `acceptor` offering `alpn` (none when empty), or `None`
/// when the handshake failed.
async fn presented_leaf(acceptor: TlsAcceptor, alpn: &[&[u8]]) -> Option<Handshake> {
	let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
	let mut config = ClientConfig::builder()
		.dangerous()
		.with_custom_certificate_verifier(Arc::new(AnyCert(provider)))
		.with_no_client_auth();
	config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
	let (client, server) = tokio::io::duplex(64 * 1024);
	let server = tokio::spawn(async move { acceptor.accept(server).await.is_ok() });
	let name = ServerName::try_from(HOST).expect("name");
	let connected = TlsConnector::from(Arc::new(config))
		.connect(name, client)
		.await
		.ok()?;
	let _ = server.await;
	let session = connected.get_ref().1;
	let leaf = session.peer_certificates()?.first()?.as_ref().to_vec();
	Some(Handshake {
		leaf,
		alpn: session.alpn_protocol().map(|p| p.to_vec()),
	})
}

fn has_acme_identifier(der: &[u8]) -> bool {
	use x509_parser::prelude::FromDer;
	let (_, cert) = x509_parser::certificate::X509Certificate::from_der(der).expect("parse");
	cert.extensions()
		.iter()
		.any(|extension| extension.oid.to_id_string() == ACME_IDENTIFIER)
}

/// Which certificate a handshake got, named so a failing assertion prints a
/// word rather than the DER bytes.
/// The CA requires `acme-tls/1` to be negotiated (RFC 8737 §3), so a
/// challenge certificate without it counts as a failure.
fn which(handshake: Option<Handshake>, normal: &[u8]) -> &'static str {
	let Some(Handshake { leaf, alpn }) = handshake else {
		return "handshake refused";
	};
	let acme = alpn.as_deref() == Some(b"acme-tls/1".as_slice());
	match (leaf == normal, has_acme_identifier(&leaf), acme) {
		(true, _, false) => "normal certificate",
		(true, _, true) => "normal certificate under acme-tls/1",
		(false, true, true) => "challenge certificate",
		(false, true, false) => "challenge certificate without acme-tls/1 negotiated",
		(false, false, _) => "unexpected certificate",
	}
}

const ACME: &[&[u8]] = &[b"acme-tls/1"];

#[tokio::test]
async fn challenge_certificate_only_for_acme_alpn_while_pending() {
	let (acceptor, normal) = normal_acceptor();
	let store = Arc::new(AlpnChallengeStore::new());
	let reloadable = ReloadableAcceptor::with_acme_alpn(acceptor, store.clone());
	let handshake = |alpn: &'static [&'static [u8]]| {
		let acceptor = reloadable.current();
		let normal = normal.clone();
		async move { which(presented_leaf(acceptor, alpn).await, &normal) }
	};

	// No order pending: an acme-tls/1 handshake has nothing to be served.
	assert_eq!(handshake(ACME).await, "handshake refused");

	store.set(HOST, "token.thumbprint").expect("set");
	assert_eq!(handshake(ACME).await, "challenge certificate");
	// Ordinary handshakes keep the normal certificate during the order,
	// with or without a mail ALPN identifier.
	assert_eq!(handshake(&[]).await, "normal certificate");
	assert_eq!(handshake(&[b"imap"]).await, "normal certificate");

	store.remove(HOST);
	assert_eq!(handshake(ACME).await, "handshake refused");
	assert_eq!(handshake(&[]).await, "normal certificate");
}

#[tokio::test]
async fn renewal_still_reaches_ordinary_handshakes() {
	let (acceptor, _) = normal_acceptor();
	let store = Arc::new(AlpnChallengeStore::new());
	let reloadable = ReloadableAcceptor::with_acme_alpn(acceptor, store);
	let (renewed, renewed_leaf) = normal_acceptor();
	reloadable.reload(renewed);
	assert_eq!(
		which(
			presented_leaf(reloadable.current(), &[]).await,
			&renewed_leaf
		),
		"normal certificate"
	);
}
