use super::*;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

const POLICY: &str = "version: STSv1\nmode: testing\nmx: mail.example.org\nmax_age: 604800\n";
const PATH: &str = "/.well-known/mta-sts.txt";

fn fixture() -> (
	tempfile::TempDir,
	Server,
	rcgen::CertifiedKey<rcgen::KeyPair>,
) {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir(dir.path().join("policy")).expect("policy dir");
	std::fs::write(dir.path().join("policy/mta-sts.txt"), POLICY).expect("policy");
	let certified = rcgen::generate_simple_self_signed(vec!["mta-sts.example.org".into()])
		.expect("certificate");
	let tls = crate::config::Tls {
		cert_file: dir.path().join("cert.pem"),
		key_file: dir.path().join("key.pem"),
		client_ca: None,
	};
	std::fs::write(&tls.cert_file, certified.cert.pem()).expect("certificate");
	std::fs::write(&tls.key_file, certified.signing_key.serialize_pem()).expect("key");
	let server = Server::new(dir.path().join("policy"), tls).expect("server");
	(dir, server, certified)
}

async fn read_closed(stream: &mut TcpStream) -> std::io::Result<usize> {
	let mut byte = [0u8; 1];
	let outcome = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut byte)).await??;
	Ok(outcome)
}

#[tokio::test]
async fn permits_burst_to_limit_and_drops_the_next() {
	crate::tls::ensure_crypto_provider();
	let (_dir, server, certified) = fixture();
	let server = server.with_max_connections(2);
	let metrics = Arc::new(crate::metrics::Metrics::new());
	let listener = TcpListener::bind("127.0.0.1:0")
		.await
		.expect("loopback bind");
	let addr = listener.local_addr().expect("address");
	let task = tokio::spawn(server.serve(listener, Arc::clone(&metrics)));

	// Two connections inside the cap, one connection over it.
	let s1 = TcpStream::connect(addr).await.expect("connect 1");
	let s2 = TcpStream::connect(addr).await.expect("connect 2");
	let mut s3 = TcpStream::connect(addr).await.expect("connect 3");

	// The third is closed before the TLS handshake even starts.
	let closed = read_closed(&mut s3).await.expect("third connection closed");
	assert_eq!(
		closed, 0,
		"third connection must be closed without a TLS handshake"
	);

	let snapshot = metrics.snapshot();
	let dropped = snapshot
		.get("mta_sts_connections_dropped")
		.copied()
		.unwrap_or_default();
	assert_eq!(
		dropped, 1,
		"counter reads 1 after the dropped third connection"
	);

	// Free the first two permits and confirm a fourth connection is served.
	drop(s1);
	drop(s2);
	let mut roots = RootCertStore::empty();
	roots
		.add(certified.cert.der().clone())
		.expect("trust anchor");
	let config = ClientConfig::builder()
		.with_root_certificates(roots)
		.with_no_client_auth();
	let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
	let mut attempts = 0;
	let mut s4 = None;
	while attempts < 100 {
		match TcpStream::connect(addr).await {
			Ok(stream) => {
				s4 = Some(stream);
				break;
			}
			Err(_) => {
				attempts += 1;
				tokio::time::sleep(Duration::from_millis(20)).await;
			}
		}
	}
	let s4 = s4.expect("fourth connect");
	let mut tls = connector
		.connect("mta-sts.example.org".try_into().expect("name"), s4)
		.await
		.expect("fourth TLS handshake");
	tls.write_all(
		format!("GET {PATH} HTTP/1.1\r\nHost: mta-sts.example.org\r\nConnection: close\r\n\r\n")
			.as_bytes(),
	)
	.await
	.expect("write request");
	let mut response = String::new();
	tls.read_to_string(&mut response)
		.await
		.expect("read response");
	assert!(
		response.starts_with("HTTP/1.1 200 "),
		"fourth connection must be served, got {}",
		response.lines().next().unwrap_or("missing status")
	);
	assert!(response.contains(POLICY));

	task.abort();
	let _ = task.await;
}

#[tokio::test]
async fn excessive_listener_cap_still_accepts_a_tls_handshake() {
	crate::tls::ensure_crypto_provider();
	let (_dir, server, certified) = fixture();
	let (listener, client) = crate::net::accept::tests::scripted::failing_then_connecting(&[]);
	let task = tokio::spawn(
		server
			.with_max_connections(usize::MAX)
			.serve_on(listener, Arc::new(crate::metrics::Metrics::new())),
	);
	let mut roots = RootCertStore::empty();
	roots
		.add(certified.cert.der().clone())
		.expect("trust anchor");
	let config = ClientConfig::builder()
		.with_root_certificates(roots)
		.with_no_client_auth();
	let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
	tokio::time::timeout(Duration::from_secs(5), async {
		connector
			.connect("mta-sts.example.org".try_into().expect("name"), client)
			.await
			.expect("handshake")
	})
	.await
	.expect("handshake deadline");
	task.abort();
}

/// A scripted accept loop fed one pre-connected stream per call, with the
/// peer address the test names. Used to exercise the per-IP admission
/// path with two distinct peers without binding real TCP. The shared
/// queue lives behind an `Arc`, so the test can push streams after the
/// listener is handed to the server.
#[derive(Clone)]
struct ScriptedPeer {
	streams: std::sync::Arc<std::sync::Mutex<Vec<(tokio::io::DuplexStream, std::net::SocketAddr)>>>,
}

impl ScriptedPeer {
	fn new() -> Self {
		Self {
			streams: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
		}
	}

	fn push(&self, peer: std::net::SocketAddr) -> tokio::io::DuplexStream {
		let (client, server) = tokio::io::duplex(64 * 1024);
		self.streams.lock().expect("script").push((server, peer));
		client
	}
}

impl crate::net::accept::Accept for ScriptedPeer {
	type Stream = tokio::io::DuplexStream;

	fn accept(
		&self,
	) -> impl std::future::Future<
		Output = std::io::Result<(tokio::io::DuplexStream, std::net::SocketAddr)>,
	> + Send {
		// FIFO: the test pushes streams in the order the server must
		// accept them, and the first one must take the first per-IP slot.
		let next = self.streams.try_lock().ok().and_then(|mut g| {
			if g.is_empty() {
				None
			} else {
				Some(g.remove(0))
			}
		});
		async move {
			match next {
				Some((stream, peer)) => Ok((stream, peer)),
				None => std::future::pending().await,
			}
		}
	}
}

/// Two connections from the same peer fill the per-IP quota and the third
/// handshake fails before any ClientHello reaches the wire. A second peer
/// still gets in while the first holds the whole quota, so the cap is
/// per-IP, not per-listener.
#[tokio::test]
async fn per_ip_admission_is_enforced_before_the_tls_handshake() {
	crate::tls::ensure_crypto_provider();
	let (_dir, server, certified) = fixture();
	let listener = ScriptedPeer::new();
	let peer_a: std::net::SocketAddr = "203.0.113.1:4000".parse().expect("peer a");
	let peer_b: std::net::SocketAddr = "203.0.113.2:4000".parse().expect("peer b");
	let metrics = Arc::new(crate::metrics::Metrics::new());
	let server = server
		.with_max_connections(10)
		.with_max_connections_per_ip(1);
	// Pre-push the first three streams (peer_a held, peer_a refused,
	// peer_b admitted) so the listener can be moved into `serve_on`
	// before any handshake runs.
	let held = listener.push(peer_a);
	let client_same = listener.push(peer_a);
	let client_other = listener.push(peer_b);
	let task = tokio::spawn(server.serve_on(listener, Arc::clone(&metrics)));

	let mut roots = RootCertStore::empty();
	roots
		.add(certified.cert.der().clone())
		.expect("trust anchor");
	let config = ClientConfig::builder()
		.with_root_certificates(roots)
		.with_no_client_auth();
	let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
	let same_peer = tokio::time::timeout(
		Duration::from_secs(3),
		connector.connect("mta-sts.example.org".try_into().expect("name"), client_same),
	)
	.await
	.expect("second handshake timed out (the server must close before the handshake completes)")
	.err();
	assert!(
		same_peer.is_some(),
		"second handshake from the same peer must fail while its quota is full"
	);
	// A different peer address still gets in: the per-IP cap is local
	// to peer_a, peer_b is unaffected.
	let other_peer = tokio::time::timeout(
		Duration::from_secs(5),
		connector.connect(
			"mta-sts.example.org".try_into().expect("name"),
			client_other,
		),
	)
	.await
	.expect("third handshake deadline")
	.expect("peer_b must be admitted while peer_a still holds its quota");
	drop(other_peer);
	// Releasing the held stream brings the per-IP slot back for peer_a.
	drop(held);

	let dropped = metrics
		.snapshot()
		.get("mta_sts_connections_dropped")
		.copied()
		.unwrap_or_default();
	assert!(
		dropped >= 1,
		"the second handshake from peer_a is counted as a dropped connection"
	);

	task.abort();
}
