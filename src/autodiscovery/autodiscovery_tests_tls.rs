//! Tests for the autoconfig listener over TLS and over plain HTTP.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::tls::ReloadableAcceptor;
use crate::tls::test_support::acceptor_and_cert;

const AUTOCONFIG: &str = "GET /mail/config-v1.1.xml?emailaddress=alice@example.org HTTP/1.1\r\n\
Host: autoconfig.example.org\r\nConnection: close\r\n\r\n";

async fn start(tls: Option<TlsAcceptor>) -> SocketAddr {
	start_capped(tls, 8).await
}

async fn start_capped(tls: Option<TlsAcceptor>, max_connections: usize) -> SocketAddr {
	let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
	let addr = listener.local_addr().expect("local addr");
	let router = super::router(
		"mail.example.org".to_string(),
		vec!["example.org".to_string()],
	);
	tokio::spawn(super::serve(
		listener,
		router,
		tls,
		max_connections,
		Default::default(),
	));
	addr
}

fn connector(trusted: CertificateDer<'static>) -> TlsConnector {
	let mut roots = RootCertStore::empty();
	roots.add(trusted).expect("trust anchor");
	let mut config = ClientConfig::builder()
		.with_root_certificates(roots)
		.with_no_client_auth();
	config.alpn_protocols = vec![b"http/1.1".to_vec()];
	TlsConnector::from(Arc::new(config))
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S) -> String {
	stream
		.write_all(AUTOCONFIG.as_bytes())
		.await
		.expect("write request");
	let mut response = Vec::new();
	let _ = stream.read_to_end(&mut response).await;
	String::from_utf8_lossy(&response).into_owned()
}

fn server_name() -> ServerName<'static> {
	ServerName::try_from("mail.example.org").expect("server name")
}

#[tokio::test]
async fn tls_listener_serves_autoconfig_after_handshake() {
	let (acceptor, cert) = acceptor_and_cert();
	let reloadable = ReloadableAcceptor::new(acceptor);
	let addr = start(Some(reloadable.https())).await;
	let tcp = TcpStream::connect(addr).await.expect("connect");
	let handshake = connector(cert).connect(server_name(), tcp).await;
	assert!(
		handshake.is_ok(),
		"TLS handshake failed: {:?}",
		handshake.as_ref().err()
	);
	let tls = handshake.expect("checked above");
	assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));
	let response = exchange(tls).await;
	assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
	assert!(
		response.contains("<emailProvider id=\"example.org\">"),
		"{response}"
	);
}

#[tokio::test]
async fn an_unset_connection_cap_serves_instead_of_refusing_everyone() {
	// `max_connections_per_listener` absent reaches the listener as 0.
	let (acceptor, cert) = acceptor_and_cert();
	let reloadable = ReloadableAcceptor::new(acceptor);
	let addr = start_capped(Some(reloadable.https()), 0).await;
	let tcp = TcpStream::connect(addr).await.expect("connect");
	let tls = connector(cert)
		.connect(server_name(), tcp)
		.await
		.expect("a cap of 0 means the default, not a closed door");
	let response = exchange(tls).await;
	assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
}

#[tokio::test]
async fn tls_listener_presents_a_renewed_certificate() {
	let (acceptor, _) = acceptor_and_cert();
	let reloadable = ReloadableAcceptor::new(acceptor);
	let addr = start(Some(reloadable.https())).await;
	// A renewal published after the listener started reaches new handshakes.
	let (renewed, renewed_cert) = acceptor_and_cert();
	reloadable.reload(renewed);
	let tcp = TcpStream::connect(addr).await.expect("connect");
	let handshake = connector(renewed_cert).connect(server_name(), tcp).await;
	assert!(
		handshake.is_ok(),
		"handshake against the renewed certificate failed: {:?}",
		handshake.as_ref().err()
	);
}

#[tokio::test]
async fn plain_listener_still_serves_http() {
	let addr = start(None).await;
	let tcp = TcpStream::connect(addr).await.expect("connect");
	let response = exchange(tcp).await;
	assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
	assert!(
		response.contains("<emailProvider id=\"example.org\">"),
		"{response}"
	);
}
