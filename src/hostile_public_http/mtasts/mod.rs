use std::sync::Arc;

use super::harness::{Certificate, Peer, TlsClient, assert_status, exchange, request, slowloris};

const PATH: &str = "/.well-known/mta-sts.txt";
const POLICY: &str = "version: STSv1\nmode: testing\nmx: mail.example.org\nmax_age: 600\n";

struct Fixture {
	peer: Peer,
	cert: Certificate,
	_dir: tempfile::TempDir,
}

impl Fixture {
	fn new() -> Self {
		let dir = tempfile::tempdir().expect("policy directory");
		std::fs::write(dir.path().join("mta-sts.txt"), POLICY).expect("policy fixture");
		std::fs::write(dir.path().join("private.txt"), "private-sentinel")
			.expect("private fixture");
		let cert = Certificate::new();
		let server = crate::mtasts::server::Server::new(dir.path().into(), cert.tls.clone())
			.expect("server");
		let peer = Peer::start(|incoming| {
			server.serve_on(incoming, Arc::new(crate::metrics::Metrics::new()))
		});
		Self {
			peer,
			cert,
			_dir: dir,
		}
	}

	async fn connect(&self) -> TlsClient {
		self.cert.connect(self.peer.connect().await).await
	}

	async fn healthy(&self) {
		self.peer.healthy(self.connect().await, PATH, POLICY).await;
	}
}

#[tokio::test]
async fn traversal_nul_and_wrong_methods_never_serve_policy() {
	let fixture = Fixture::new();
	fixture.healthy().await;
	for path in [
		"/.well-known/../private.txt",
		"/.well-known/%2e%2e/private.txt",
		"/.well-known/mta-sts.txt%00",
		"/.well-known/mta-sts.txt/../private.txt",
	] {
		let reply = exchange(fixture.connect().await, &request(path, "mail.example.org")).await;
		assert_status(&reply, 404);
		assert!(!reply.contains("private-sentinel"));
		assert!(!reply.contains(POLICY));
		fixture.healthy().await;
	}
	let reply = exchange(
		fixture.connect().await,
		&request(PATH, "mail.example.org").replacen("GET ", "POST ", 1),
	)
	.await;
	assert_status(&reply, 405);
	fixture.healthy().await;
}

#[tokio::test]
async fn dripping_mtasts_headers_close_by_deadline() {
	let fixture = Fixture::new();
	fixture.healthy().await;
	slowloris(fixture.connect().await, PATH).await;
	fixture.healthy().await;
}
