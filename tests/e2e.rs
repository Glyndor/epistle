//! Full-server end-to-end test against a real, already-running `epistle serve`.
//!
//! Unlike `tests/interop.rs` (which binds epistle's servers in-process), this
//! test drives the actual shipped binary over real TCP ports with implicit TLS:
//! it submits a message through the `submissions` listener and retrieves it back
//! through the `imaps` listener, proving the whole pipeline — TLS, SASL auth,
//! local delivery, the on-disk store and the IMAP read path — works as the
//! deployed daemon.
//!
//! It runs ONLY when the `E2E_*` environment variables are set (the e2e
//! workflow, or a local operator, starts the server and exports them);
//! otherwise it prints "skipping" and returns, so the default `cargo test` run
//! never needs a live server. This mirrors the skip-when-unset gating of
//! `tests/interop.rs` and `tests/database.rs`.
//!
//! Required environment:
//! - `E2E_HOST` — host the server listens on (e.g. `127.0.0.1`).
//! - `E2E_SUBMISSION_PORT` — the `submissions` implicit-TLS port (e.g. 4465).
//! - `E2E_IMAPS_PORT` — the `imaps` implicit-TLS port (e.g. 4993).
//! - `E2E_ACCOUNT` — the login / mailbox address (e.g. `tester@epistle.test`).
//! - `E2E_PASSWORD` — that account's password.
//! - `E2E_CA_PEM` — path to the server's self-signed certificate (PEM), which the
//!   TLS client below trusts as its sole root.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// Everything the test needs, read from the `E2E_*` environment. `None` when any
/// variable is unset or empty, which makes the test skip cleanly.
struct Env {
	host: String,
	server_name: String,
	submission_port: u16,
	imaps_port: u16,
	account: String,
	password: String,
	ca_pem: Vec<u8>,
}

/// Read a required, non-empty environment variable, or `None`.
fn var(name: &str) -> Option<String> {
	std::env::var(name).ok().filter(|value| !value.is_empty())
}

impl Env {
	/// Assemble the configuration from the environment, or `None` when the suite
	/// is not enabled (any variable missing) so the caller can skip.
	fn load() -> Option<Self> {
		let host = var("E2E_HOST")?;
		// The TLS server name must match the certificate's SAN, which is not the
		// loopback IP the test connects to; default to the cert name the workflow
		// generates.
		let server_name = var("E2E_SERVER_NAME").unwrap_or_else(|| "mail.epistle.test".to_string());
		let submission_port = var("E2E_SUBMISSION_PORT")?.parse().ok()?;
		let imaps_port = var("E2E_IMAPS_PORT")?.parse().ok()?;
		let account = var("E2E_ACCOUNT")?;
		let password = var("E2E_PASSWORD")?;
		let ca_pem = std::fs::read(var("E2E_CA_PEM")?).ok()?;
		Some(Self {
			host,
			server_name,
			submission_port,
			imaps_port,
			account,
			password,
			ca_pem,
		})
	}
}

/// Read one CRLF-terminated reply line from `stream` without the trailing CRLF.
/// Reads byte by byte so it never consumes past the line boundary.
async fn read_line<S>(stream: &mut S) -> String
where
	S: AsyncRead + Unpin,
{
	let mut line = Vec::new();
	let mut byte = [0u8; 1];
	loop {
		let n = stream.read(&mut byte).await.expect("read line");
		assert!(
			n != 0,
			"connection closed mid-line: {:?}",
			String::from_utf8_lossy(&line)
		);
		if byte[0] == b'\n' {
			break;
		}
		if byte[0] != b'\r' {
			line.push(byte[0]);
		}
	}
	String::from_utf8_lossy(&line).into_owned()
}

/// Read a (possibly multiline) SMTP reply and assert its status code equals
/// `expected`. A multiline reply has `-` as the fourth byte on every line but
/// the last (`250-...` then `250 ...`).
async fn expect_code<S>(stream: &mut S, expected: u16)
where
	S: AsyncRead + Unpin,
{
	loop {
		let line = read_line(stream).await;
		let code: u16 = line
			.get(..3)
			.and_then(|head| head.parse().ok())
			.unwrap_or_else(|| panic!("malformed SMTP reply: {line:?}"));
		assert_eq!(code, expected, "unexpected SMTP reply: {line:?}");
		if line.as_bytes().get(3) != Some(&b'-') {
			return;
		}
	}
}

/// Write a line plus CRLF and flush.
async fn send_line<S>(stream: &mut S, line: &str)
where
	S: AsyncWrite + Unpin,
{
	stream.write_all(line.as_bytes()).await.expect("write");
	stream.write_all(b"\r\n").await.expect("write crlf");
	stream.flush().await.expect("flush");
}

/// Read from `stream` until `needle` appears in the accumulated text, returning
/// everything read. Used for the line-oriented (but not strictly one-reply) IMAP
/// responses.
async fn read_until<S>(stream: &mut S, needle: &str) -> String
where
	S: AsyncRead + Unpin,
{
	let mut got = String::new();
	let mut chunk = [0u8; 4096];
	while !got.contains(needle) {
		let n = stream.read(&mut chunk).await.expect("read");
		assert!(n != 0, "closed waiting for {needle:?}: {got}");
		got.push_str(&String::from_utf8_lossy(&chunk[..n]));
	}
	got
}

/// Complete a TLS handshake to `name`, trusting only `ca_pem` (the server's
/// self-signed certificate from `E2E_CA_PEM`). Returns the encrypted stream.
async fn tls_client_connect(
	tcp: TcpStream,
	name: String,
	ca_pem: &[u8],
) -> tokio_rustls::client::TlsStream<TcpStream> {
	use tokio_rustls::TlsConnector;
	use tokio_rustls::rustls::pki_types::CertificateDer;
	use tokio_rustls::rustls::pki_types::ServerName;
	use tokio_rustls::rustls::pki_types::pem::PemObject;
	use tokio_rustls::rustls::{ClientConfig, RootCertStore};

	epistle::tls::ensure_crypto_provider();
	let mut roots = RootCertStore::empty();
	for cert in CertificateDer::pem_slice_iter(ca_pem) {
		roots.add(cert.expect("parse cert")).expect("trust cert");
	}
	let config = ClientConfig::builder()
		.with_root_certificates(roots)
		.with_no_client_auth();
	let server_name = ServerName::try_from(name).expect("server name");
	TlsConnector::from(Arc::new(config))
		.connect(server_name, tcp)
		.await
		.expect("tls handshake")
}

/// Encode a SASL PLAIN response (`\0authcid\0password`) as base64, the argument
/// to `AUTH PLAIN`.
fn sasl_plain(authcid: &str, password: &str) -> String {
	use base64::Engine;
	base64::engine::general_purpose::STANDARD.encode(format!("\0{authcid}\0{password}"))
}

/// Submit a message for `account` (from and to itself) through the implicit-TLS
/// `submissions` port, authenticating with `AUTH PLAIN`. The `marker` is the
/// unique subject the IMAP side later searches for. Returns once the server has
/// accepted the message (final 250).
async fn submit(env: &Env, marker: &str) {
	let addr = format!("{}:{}", env.host, env.submission_port);
	let tcp = TcpStream::connect(&addr).await.expect("connect submission");
	let mut tls = tls_client_connect(tcp, env.server_name.clone(), &env.ca_pem).await;

	expect_code(&mut tls, 220).await;
	send_line(&mut tls, "EHLO e2e.client.test").await;
	expect_code(&mut tls, 250).await;
	send_line(
		&mut tls,
		&format!("AUTH PLAIN {}", sasl_plain(&env.account, &env.password)),
	)
	.await;
	expect_code(&mut tls, 235).await;
	send_line(&mut tls, &format!("MAIL FROM:<{}>", env.account)).await;
	expect_code(&mut tls, 250).await;
	send_line(&mut tls, &format!("RCPT TO:<{}>", env.account)).await;
	expect_code(&mut tls, 250).await;
	send_line(&mut tls, "DATA").await;
	expect_code(&mut tls, 354).await;
	let body = format!(
		"From: {0}\r\nTo: {0}\r\nSubject: {marker}\r\n\r\nbody {marker}\r\n.\r\n",
		env.account
	);
	tls.write_all(body.as_bytes()).await.expect("write data");
	tls.flush().await.expect("flush data");
	expect_code(&mut tls, 250).await;
	send_line(&mut tls, "QUIT").await;
	expect_code(&mut tls, 221).await;
}

/// Open the `imaps` port over TLS, log in, SELECT INBOX and FETCH every message,
/// returning the concatenated FETCH text. A fresh connection per poll keeps the
/// IMAP state simple.
async fn fetch_all(env: &Env) -> String {
	let addr = format!("{}:{}", env.host, env.imaps_port);
	let tcp = TcpStream::connect(&addr).await.expect("connect imaps");
	let mut tls = tls_client_connect(tcp, env.server_name.clone(), &env.ca_pem).await;

	read_until(&mut tls, "OK").await;
	send_line(
		&mut tls,
		&format!("a1 LOGIN {} {}", env.account, env.password),
	)
	.await;
	read_until(&mut tls, "a1 OK").await;
	send_line(&mut tls, "a2 SELECT INBOX").await;
	let select = read_until(&mut tls, "a2 OK").await;
	// No message yet: report an empty mailbox so the caller keeps polling.
	if select.contains("* 0 EXISTS") {
		send_line(&mut tls, "a3 LOGOUT").await;
		let _ = read_until(&mut tls, "a3 OK").await;
		return String::new();
	}
	send_line(&mut tls, "a3 FETCH 1:* (BODY[])").await;
	let fetch = read_until(&mut tls, "a3 OK").await;
	send_line(&mut tls, "a4 LOGOUT").await;
	let _ = read_until(&mut tls, "a4 OK").await;
	fetch
}

/// Poll the IMAP store until the `marker` arrives (delivery is near-instant
/// locally, but allow a short backoff), or fail after the deadline.
async fn poll_for_marker(env: &Env, marker: &str) -> String {
	for _ in 0..50 {
		let fetched = fetch_all(env).await;
		if fetched.contains(marker) {
			return fetched;
		}
		tokio::time::sleep(Duration::from_millis(200)).await;
	}
	panic!("message with marker {marker:?} did not arrive over IMAP within the deadline");
}

#[tokio::test]
async fn submission_to_imap_round_trip() {
	let Some(env) = Env::load() else {
		eprintln!("skipping: E2E_* environment not set");
		return;
	};

	// A unique marker so a re-run never matches a message left by a prior run.
	let marker = format!("e2e-{}", uuid::Uuid::now_v7());
	submit(&env, &marker).await;

	let fetched = poll_for_marker(&env, &marker).await;
	assert!(
		fetched.contains(&format!("Subject: {marker}")),
		"FETCH missing subject marker: {fetched}"
	);
	assert!(
		fetched.contains(&format!("body {marker}")),
		"FETCH missing body marker: {fetched}"
	);
}
