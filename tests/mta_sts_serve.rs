//! Loopback HTTPS checks for the public MTA-STS endpoint.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use epistle::config::Tls;
use epistle::mtasts::server::Server;
use reqwest::{Client, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

const POLICY: &str = "version: STSv1\nmode: testing\nmx: mail.example.org\nmax_age: 604800\n";
const PATH: &str = "/.well-known/mta-sts.txt";

struct Fixture {
	dir: tempfile::TempDir,
	addr: SocketAddr,
	cert: rcgen::CertifiedKey<rcgen::KeyPair>,
	client: Client,
	task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Drop for Fixture {
	fn drop(&mut self) {
		self.task.abort();
	}
}

fn certificate() -> rcgen::CertifiedKey<rcgen::KeyPair> {
	rcgen::generate_simple_self_signed(vec!["mta-sts.example.org".into()]).expect("certificate")
}

fn client(cert: &rcgen::CertifiedKey<rcgen::KeyPair>, addr: SocketAddr) -> Client {
	Client::builder()
		.no_proxy()
		.tls_certs_only([reqwest::Certificate::from_der(cert.cert.der()).expect("trust anchor")])
		.resolve("mta-sts.example.org", addr)
		.timeout(Duration::from_secs(5))
		.pool_max_idle_per_host(0)
		.build()
		.expect("HTTPS client")
}

impl Fixture {
	async fn start() -> Self {
		epistle::tls::ensure_crypto_provider();
		let dir = tempfile::tempdir().expect("tempdir");
		std::fs::create_dir(dir.path().join("policy")).expect("policy directory");
		std::fs::write(dir.path().join("policy/mta-sts.txt"), POLICY).expect("policy");
		std::fs::write(
			dir.path().join("mail.toml"),
			"sentinel outside the public directory",
		)
		.expect("sentinel");
		std::fs::write(
			dir.path().join("policy/other"),
			"another public-directory file",
		)
		.expect("other file");
		let cert = certificate();
		let tls = Tls {
			cert_file: dir.path().join("cert.pem"),
			key_file: dir.path().join("key.pem"),
			client_ca: None,
		};
		std::fs::write(&tls.cert_file, cert.cert.pem()).expect("certificate PEM");
		std::fs::write(&tls.key_file, cert.signing_key.serialize_pem()).expect("private PEM");
		let server = Server::new(dir.path().join("policy"), tls).expect("server");
		let listener = TcpListener::bind("127.0.0.1:0")
			.await
			.expect("loopback bind");
		let addr = listener.local_addr().expect("address");
		let client = client(&cert, addr);
		let task = tokio::spawn(server.serve(listener));
		Self {
			dir,
			addr,
			cert,
			client,
			task,
		}
	}

	fn url(&self, path: &str) -> String {
		format!("https://mta-sts.example.org:{}{path}", self.addr.port())
	}

	fn policy_file(&self) -> PathBuf {
		self.dir.path().join("policy/mta-sts.txt")
	}

	async fn raw(&self, request: &str) -> String {
		let mut roots = RootCertStore::empty();
		roots.add(self.cert.cert.der().clone()).expect("trust");
		let config = ClientConfig::builder()
			.with_root_certificates(roots)
			.with_no_client_auth();
		let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
		tokio::time::timeout(Duration::from_secs(5), async {
			let stream = TcpStream::connect(self.addr).await.expect("connect");
			let mut tls = connector
				.connect("mta-sts.example.org".try_into().expect("name"), stream)
				.await
				.expect("TLS handshake");
			tls.write_all(request.as_bytes()).await.expect("request");
			let mut response = String::new();
			tls.read_to_string(&mut response).await.expect("response");
			response
		})
		.await
		.expect("HTTP response deadline")
	}
}

#[tokio::test]
async fn get_and_head_return_exact_policy_and_cache_headers() {
	let fixture = Fixture::start().await;
	let response = fixture
		.client
		.get(fixture.url(PATH))
		.send()
		.await
		.expect("GET");
	assert_eq!(response.status(), StatusCode::OK);
	assert_eq!(
		response.headers()["content-type"],
		"text/plain; charset=utf-8"
	);
	assert_eq!(response.headers()["cache-control"], "max-age=604800");
	assert_eq!(
		response.bytes().await.expect("body").as_ref(),
		POLICY.as_bytes()
	);
	let head = fixture
		.client
		.head(fixture.url(PATH))
		.send()
		.await
		.expect("HEAD");
	assert_eq!(head.status(), StatusCode::OK);
	assert_eq!(head.headers()["content-type"], "text/plain; charset=utf-8");
	assert_eq!(head.headers()["cache-control"], "max-age=604800");
	assert_eq!(head.headers()["content-length"], POLICY.len().to_string());
	assert!(head.bytes().await.expect("HEAD body").is_empty());
}

#[tokio::test]
async fn only_exact_policy_path_is_served() {
	let fixture = Fixture::start().await;
	for path in [
		"/",
		"/.well-known/other",
		"/.well-known/mta-sts.txt/../mail.toml",
		"/.well-known/mta-sts.txt/%2e%2e/mail.toml",
		"/.well-known/%2e%2e/%2e%2e/mail.toml",
		"/.well-known/mta-sts.txt%2f..%2fmail.toml",
	] {
		let response = fixture
			.client
			.get(fixture.url(path))
			.send()
			.await
			.expect("GET unknown path");
		assert_eq!(response.status(), StatusCode::NOT_FOUND, "path {path}");
		let body = response.bytes().await.expect("body");
		assert!(!String::from_utf8_lossy(&body).contains("sentinel outside"));
		assert!(body.is_empty());
		let raw = fixture
			.raw(&format!(
				"GET {path} HTTP/1.1\r\nHost: mta-sts.example.org\r\nConnection: close\r\n\r\n"
			))
			.await;
		assert!(raw.starts_with("HTTP/1.1 404 "), "raw path {path}: {raw}");
		assert!(!raw.contains("sentinel outside"));
		assert_eq!(raw.split_once("\r\n\r\n").expect("headers").1, "");
	}
}

#[tokio::test]
async fn unsupported_methods_are_405_only_on_policy_path() {
	let fixture = Fixture::start().await;
	for method in [
		reqwest::Method::POST,
		reqwest::Method::PUT,
		reqwest::Method::DELETE,
		reqwest::Method::OPTIONS,
		reqwest::Method::PATCH,
	] {
		let response = fixture
			.client
			.request(method.clone(), fixture.url(PATH))
			.send()
			.await
			.expect("method");
		assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
		assert_eq!(response.headers()["allow"], "GET, HEAD");
		assert!(response.bytes().await.expect("body").is_empty());
		let other = fixture
			.client
			.request(method, fixture.url("/"))
			.send()
			.await
			.expect("unknown path");
		assert_eq!(other.status(), StatusCode::NOT_FOUND);
		assert!(other.bytes().await.expect("body").is_empty());
	}
}

#[tokio::test]
async fn policy_changes_and_deletion_are_visible_without_restart() {
	let fixture = Fixture::start().await;
	let updated = POLICY.replace("604800", "120");
	std::fs::write(fixture.policy_file(), &updated).expect("update policy");
	let response = fixture
		.client
		.get(fixture.url(PATH))
		.send()
		.await
		.expect("GET changed");
	assert_eq!(response.status(), StatusCode::OK);
	assert_eq!(response.headers()["cache-control"], "max-age=120");
	assert_eq!(response.text().await.expect("body"), updated);
	std::fs::remove_file(fixture.policy_file()).expect("remove policy");
	let response = fixture
		.client
		.get(fixture.url(PATH))
		.send()
		.await
		.expect("GET missing");
	assert_eq!(response.status(), StatusCode::NOT_FOUND);
	assert!(response.bytes().await.expect("missing body").is_empty());
	std::fs::write(fixture.policy_file(), POLICY).expect("restore policy");
	let response = fixture
		.client
		.get(fixture.url(PATH))
		.send()
		.await
		.expect("GET restored");
	assert_eq!(response.status(), StatusCode::OK);
	assert_eq!(response.text().await.expect("body"), POLICY);
	assert!(!fixture.task.is_finished());
}

#[tokio::test]
async fn request_line_and_headers_are_limited_to_eight_kib() {
	let fixture = Fixture::start().await;
	for oversized_uri in [false, true] {
		for (size, status) in [(8191, "200"), (8193, "431")] {
			let base = if oversized_uri {
				format!(
					"GET {PATH}? HTTP/1.1\r\nHost: mta-sts.example.org\r\nConnection: close\r\n\r\n"
				)
			} else {
				format!(
					"GET {PATH} HTTP/1.1\r\nHost: mta-sts.example.org\r\nConnection: close\r\nX-Padding: \r\n\r\n"
				)
			};
			let padding = "x".repeat(size - base.len());
			let request = if oversized_uri {
				base.replace("? ", &format!("?{padding} "))
			} else {
				base.replace("X-Padding: ", &format!("X-Padding: {padding}"))
			};
			assert_eq!(request.len(), size);
			let response = fixture.raw(&request).await;
			assert!(
				response.starts_with(&format!("HTTP/1.1 {status} ")),
				"head size {size}, URI {oversized_uri}: {}",
				response.lines().next().unwrap_or("no status")
			);
		}
	}
}

#[tokio::test]
async fn certificate_replacement_is_used_on_the_next_connection() {
	let fixture = Fixture::start().await;
	let first = fixture
		.client
		.get(fixture.url(PATH))
		.send()
		.await
		.expect("initial certificate");
	assert_eq!(first.status(), StatusCode::OK);
	let replacement = certificate();
	for (name, contents) in [
		("cert.pem", replacement.cert.pem()),
		("key.pem", replacement.signing_key.serialize_pem()),
	] {
		let temporary = fixture.dir.path().join(format!("{name}.new"));
		std::fs::write(&temporary, contents).expect("replacement");
		std::fs::rename(temporary, fixture.dir.path().join(name)).expect("replace TLS material");
	}
	let fresh_client = client(&replacement, fixture.addr);
	let response = fresh_client
		.get(fixture.url(PATH))
		.send()
		.await
		.expect("reloaded certificate");
	assert_eq!(response.status(), StatusCode::OK);
	std::fs::write(
		fixture.dir.path().join("cert.pem"),
		"incomplete certificate",
	)
	.expect("invalid replacement");
	let retained = fresh_client
		.get(fixture.url(PATH))
		.send()
		.await
		.expect("previous valid certificate retained");
	assert_eq!(retained.status(), StatusCode::OK);
}
