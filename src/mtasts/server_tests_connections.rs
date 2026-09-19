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
