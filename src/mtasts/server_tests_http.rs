use super::*;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

const POLICY: &str = "version: STSv1\nmode: testing\nmx: mail.example.org\nmax_age: 604800\n";

struct Fixture {
	dir: tempfile::TempDir,
	server: Server,
	connector: tokio_rustls::TlsConnector,
}

impl Fixture {
	fn new() -> Self {
		let dir = tempfile::tempdir().expect("tempdir");
		std::fs::create_dir(dir.path().join("policy")).expect("policy dir");
		std::fs::write(dir.path().join("policy/mta-sts.txt"), POLICY).expect("policy");
		std::fs::write(
			dir.path().join("mail.toml"),
			"sentinel outside policy directory",
		)
		.expect("sentinel");
		std::fs::write(dir.path().join("policy/other"), "other file").expect("other file");
		let certified = rcgen::generate_simple_self_signed(vec!["mta-sts.example.org".into()])
			.expect("certificate");
		let tls = Tls {
			cert_file: dir.path().join("cert.pem"),
			key_file: dir.path().join("key.pem"),
			client_ca: None,
		};
		std::fs::write(&tls.cert_file, certified.cert.pem()).expect("certificate");
		std::fs::write(&tls.key_file, certified.signing_key.serialize_pem()).expect("key");
		let server = Server::new(dir.path().join("policy"), tls).expect("server");
		let mut roots = RootCertStore::empty();
		roots.add(certified.cert.der().clone()).expect("trust");
		let client = ClientConfig::builder()
			.with_root_certificates(roots)
			.with_no_client_auth();
		Self {
			dir,
			server,
			connector: tokio_rustls::TlsConnector::from(Arc::new(client)),
		}
	}

	async fn raw(&mut self, request: &str) -> String {
		let (client, server) = tokio::io::duplex(32768);
		let serve = connection(
			server,
			self.server.tls.current(),
			self.server.router.clone(),
		);
		let exchange = async {
			let mut tls = self
				.connector
				.connect("mta-sts.example.org".try_into().expect("name"), client)
				.await
				.expect("TLS handshake");
			tls.write_all(request.as_bytes()).await.expect("request");
			let mut response = String::new();
			tls.read_to_string(&mut response).await.expect("response");
			response
		};
		tokio::time::timeout(Duration::from_secs(5), async {
			tokio::join!(serve, exchange).1
		})
		.await
		.expect("exchange deadline")
	}

	async fn request(&mut self, method: &str, path: &str) -> String {
		self.raw(&format!(
			"{method} {path} HTTP/1.1\r\nHost: mta-sts.example.org\r\nConnection: close\r\n\r\n"
		))
		.await
	}
}

fn assert_response(response: &str, status: u16, body: &str) {
	assert!(
		response.starts_with(&format!("HTTP/1.1 {status} ")),
		"{}",
		response.lines().next().unwrap_or("missing status")
	);
	assert_eq!(
		response
			.split_once("\r\n\r\n")
			.expect("header terminator")
			.1,
		body
	);
}

#[tokio::test]
async fn exact_bytes_headers_and_empty_head_over_tls() {
	let mut fixture = Fixture::new();
	let get = fixture.request("GET", POLICY_PATH).await;
	assert_response(&get, 200, POLICY);
	assert!(get.contains("\r\ncontent-type: text/plain; charset=utf-8\r\n"));
	assert!(get.contains("\r\ncache-control: max-age=604800\r\n"));
	let head = fixture.request("HEAD", POLICY_PATH).await;
	assert_response(&head, 200, "");
	assert!(head.contains(&format!("\r\ncontent-length: {}\r\n", POLICY.len())));
	assert!(head.contains("\r\ncontent-type: text/plain; charset=utf-8\r\n"));
	assert!(head.contains("\r\ncache-control: max-age=604800\r\n"));
}

#[tokio::test]
async fn other_paths_and_raw_traversals_are_empty_404() {
	let mut fixture = Fixture::new();
	assert_response(&fixture.request("GET", POLICY_PATH).await, 200, POLICY);
	for path in [
		"/",
		"/.well-known/other",
		"/.well-known/mta-sts.txt/../mail.toml",
		"/.well-known/mta-sts.txt/%2e%2e/mail.toml",
		"/.well-known/%2e%2e/%2e%2e/mail.toml",
		"/.well-known/mta-sts.txt%2f..%2fmail.toml",
	] {
		let response = fixture.request("GET", path).await;
		assert!(!response.contains("sentinel outside"));
		assert_response(&response, 404, "");
	}
}

#[tokio::test]
async fn method_rejection_has_allow_header_only_at_policy_path() {
	let mut fixture = Fixture::new();
	assert_response(&fixture.request("GET", POLICY_PATH).await, 200, POLICY);
	for method in ["POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"] {
		let response = fixture.request(method, POLICY_PATH).await;
		assert_response(&response, 405, "");
		assert!(response.contains("\r\nallow: GET, HEAD\r\n"));
		assert_response(&fixture.request(method, "/").await, 404, "");
	}
}

#[tokio::test]
async fn file_is_reread_and_missing_file_is_recoverable_404() {
	let mut fixture = Fixture::new();
	assert_response(&fixture.request("GET", POLICY_PATH).await, 200, POLICY);
	let path = fixture.dir.path().join("policy/mta-sts.txt");
	let changed = POLICY.replace("604800", "120");
	std::fs::write(&path, &changed).expect("replace policy");
	let response = fixture.request("GET", POLICY_PATH).await;
	assert_response(&response, 200, &changed);
	assert!(response.contains("\r\ncache-control: max-age=120\r\n"));
	std::fs::remove_file(&path).expect("remove policy");
	assert_response(&fixture.request("GET", POLICY_PATH).await, 404, "");
	std::fs::write(&path, POLICY).expect("restore policy");
	assert_response(&fixture.request("GET", POLICY_PATH).await, 200, POLICY);
}

#[tokio::test]
async fn request_heads_just_below_limit_pass_and_above_fail_with_431() {
	let mut fixture = Fixture::new();
	for uri in [false, true] {
		for (size, status) in [(8191, 200), (8193, 431)] {
			let base = if uri {
				format!(
					"GET {POLICY_PATH}? HTTP/1.1\r\nHost: mta-sts.example.org\r\nConnection: close\r\n\r\n"
				)
			} else {
				format!(
					"GET {POLICY_PATH} HTTP/1.1\r\nHost: mta-sts.example.org\r\nConnection: close\r\nX-Padding: \r\n\r\n"
				)
			};
			let padding = "x".repeat(size - base.len());
			let request = if uri {
				base.replace("? ", &format!("?{padding} "))
			} else {
				base.replace("X-Padding: ", &format!("X-Padding: {padding}"))
			};
			assert_eq!(request.len(), size);
			let response = fixture.raw(&request).await;
			assert_response(&response, status, if status == 200 { POLICY } else { "" });
		}
	}
}
