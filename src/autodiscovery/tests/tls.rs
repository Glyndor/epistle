//! Tests for the autoconfig listener over TLS and over plain HTTP.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

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

#[tokio::test]
async fn excessive_listener_cap_still_serves_tls_autoconfig() {
	let (acceptor, cert) = acceptor_and_cert();
	let (listener, client) = crate::net::accept::tests::scripted::failing_then_connecting(&[]);
	let router = super::router("mail.example.org".into(), vec!["example.org".into()]);
	let task = tokio::spawn(super::https::serve_on(
		listener,
		router,
		Some(ReloadableAcceptor::new(acceptor).https()),
		usize::MAX,
		Default::default(),
	));
	let response = tokio::time::timeout(std::time::Duration::from_secs(5), async {
		let tls = connector(cert)
			.connect(server_name(), client)
			.await
			.expect("handshake");
		exchange(tls).await
	})
	.await
	.expect("response deadline");
	assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
	task.abort();
}

/// A second TLS handshake from the same client is refused before it
/// completes, and the slot comes back when the first connection ends.
#[tokio::test]
async fn per_ip_admission_is_enforced_before_the_tls_handshake() {
	let (acceptor, cert) = acceptor_and_cert();
	let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
	let addr = listener.local_addr().expect("addr");
	let router = super::router(
		"mail.example.org".to_string(),
		vec!["example.org".to_string()],
	);
	let limits = crate::net::http_serve::Limits {
		connections: 10,
		per_ip: 1,
	};
	let task = tokio::spawn(super::https::serve_on(
		listener,
		router,
		Some(ReloadableAcceptor::new(acceptor).https()),
		10,
		limits,
	));
	// First handshake completes; the admit guard is held by the task and
	// only released when `tls_a` is dropped, because no HTTP request is sent
	// (the listener waits `CONNECTION_TIMEOUT` for a head).
	let tcp_a = TcpStream::connect(addr).await.expect("connect a");
	let tls_a = tokio::time::timeout(
		Duration::from_secs(5),
		connector(cert.clone()).connect(server_name(), tcp_a),
	)
	.await
	.expect("handshake a timed out")
	.expect("handshake a must succeed while the per-IP slot is free");
	// Second handshake from the same client must be refused.
	let tcp_b = TcpStream::connect(addr).await.expect("connect b");
	let second = tokio::time::timeout(
		Duration::from_secs(3),
		connector(cert.clone()).connect(server_name(), tcp_b),
	)
	.await
	.expect("handshake b timed out (the server must close before the handshake completes)")
	.err();
	assert!(
		second.is_some(),
		"second handshake must fail while the per-IP slot is held"
	);
	// Drop the first connection so the admit guard returns the slot.
	drop(tls_a);
	let tcp_c = TcpStream::connect(addr).await.expect("connect c");
	let tls_c = tokio::time::timeout(
		Duration::from_secs(5),
		connector(cert.clone()).connect(server_name(), tcp_c),
	)
	.await
	.expect("handshake c timed out")
	.expect("handshake c must succeed after the per-IP slot is freed");
	let response = exchange(tls_c).await;
	assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
	task.abort();
}

/// With `per_ip` raised, two connections from the same loopback address
/// both complete handshakes; a third is refused. The loopback adapter
/// reports every client as one IPv4 address, so this exercises the same
/// per-IP path while fitting in real TCP.
#[tokio::test]
async fn per_ip_admission_admits_n_and_refuses_the_next() {
	let (acceptor, cert) = acceptor_and_cert();
	let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
	let addr = listener.local_addr().expect("addr");
	let router = super::router(
		"mail.example.org".to_string(),
		vec!["example.org".to_string()],
	);
	let limits = crate::net::http_serve::Limits {
		connections: 10,
		per_ip: 2,
	};
	let task = tokio::spawn(super::https::serve_on(
		listener,
		router,
		Some(ReloadableAcceptor::new(acceptor).https()),
		10,
		limits,
	));
	// Two simultaneous handshakes from the loopback address hold both
	// per-IP slots; no HTTP request is sent, so the admit guards stay
	// alive in their connection tasks.
	let tcp_a = TcpStream::connect(addr).await.expect("connect a");
	let tcp_b = TcpStream::connect(addr).await.expect("connect b");
	let tls_a = tokio::time::timeout(
		Duration::from_secs(5),
		connector(cert.clone()).connect(server_name(), tcp_a),
	)
	.await
	.expect("handshake a timed out")
	.expect("handshake a must succeed");
	let tls_b = tokio::time::timeout(
		Duration::from_secs(5),
		connector(cert.clone()).connect(server_name(), tcp_b),
	)
	.await
	.expect("handshake b timed out")
	.expect("handshake b must succeed while the second per-IP slot is free");
	// A third handshake from the same address must be refused.
	let tcp_c = TcpStream::connect(addr).await.expect("connect c");
	let third = tokio::time::timeout(
		Duration::from_secs(3),
		connector(cert.clone()).connect(server_name(), tcp_c),
	)
	.await
	.expect("handshake c timed out (the server must close before the handshake completes)")
	.err();
	assert!(
		third.is_some(),
		"third handshake must fail while the per-IP quota is full"
	);
	drop(tls_a);
	drop(tls_b);
	task.abort();
}
