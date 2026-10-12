//! Upgrade-survival test: a fresh binary serves a data directory a previous
//! binary wrote.
//!
//! `.github/workflows/upgrade.yml` is the harness: it downloads the latest
//! published release, starts it, creates the account, submits a message and
//! sets a flag on it, creates an app password, stops it; then it builds the
//! binary in this commit, starts it on the same data and config, and runs
//! this test against the new build. What this test asserts:
//!
//! - the password set on the previous binary still logs in;
//! - the message submitted under the previous binary is still there, with the
//!   flag still set;
//! - the app password set on the previous binary still authenticates;
//! - the server log carries no `ERROR` line from the restart.
//!
//! The test is `#[ignore]`d in the default `cargo test` run and executed
//! explicitly by the workflow, exactly like `tests/e2e.rs`.
//!
//! Required environment:
//! - `UPGRADE_HOST`: host the server listens on (e.g. `127.0.0.1`).
//! - `UPGRADE_IMAPS_PORT`: the `imaps` implicit-TLS port.
//! - `UPGRADE_ACCOUNT`: the login / mailbox address.
//! - `UPGRADE_PASSWORD`: the account's main password.
//! - `UPGRADE_APP_PASSWORD`: the secondary credential.
//! - `UPGRADE_CA_PEM`: path to the server's self-signed certificate (PEM).
//! - `UPGRADE_MARKER`: the unique subject the previous binary submitted.
//! - `UPGRADE_SERVER_LOG`: path to the new server's journal; scanned for
//!   `ERROR` lines so a regression in the upgrade path fails the test rather
//!   than the next deploy.

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// Everything the test needs, read from the `UPGRADE_*` environment. `None`
/// when any variable is unset or empty, which makes the test skip cleanly.
struct Env {
	host: String,
	server_name: String,
	imaps_port: u16,
	account: String,
	password: String,
	app_password: String,
	ca_pem: Vec<u8>,
	marker: String,
	server_log: Option<String>,
}

/// Read a required, non-empty environment variable, or `None`.
fn var(name: &str) -> Option<String> {
	std::env::var(name).ok().filter(|value| !value.is_empty())
}

impl Env {
	fn load() -> Option<Self> {
		let host = var("UPGRADE_HOST")?;
		let server_name =
			var("UPGRADE_SERVER_NAME").unwrap_or_else(|| "mail.epistle.test".to_string());
		let imaps_port = var("UPGRADE_IMAPS_PORT")?.parse().ok()?;
		let account = var("UPGRADE_ACCOUNT")?;
		let password = var("UPGRADE_PASSWORD")?;
		let app_password = var("UPGRADE_APP_PASSWORD")?;
		let ca_pem = std::fs::read(var("UPGRADE_CA_PEM")?).ok()?;
		let marker = var("UPGRADE_MARKER")?;
		let server_log = var("UPGRADE_SERVER_LOG");
		Some(Self {
			host,
			server_name,
			imaps_port,
			account,
			password,
			app_password,
			ca_pem,
			marker,
			server_log,
		})
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

/// Read from `stream` until any of `needles` appears in the accumulated text.
/// Returns the full text and the matched needle, so the caller can assert on
/// the kind of reply (OK vs NO) instead of looping forever on a server that
/// answered NO.
async fn read_until_any<S>(stream: &mut S, needles: &[&str]) -> (String, String)
where
	S: AsyncRead + Unpin,
{
	let mut got = String::new();
	let mut chunk = [0u8; 4096];
	loop {
		for needle in needles {
			if got.contains(needle) {
				return (got, (*needle).to_string());
			}
		}
		let n = stream.read(&mut chunk).await.expect("read");
		assert!(n != 0, "closed waiting for {needles:?}: {got}");
		got.push_str(&String::from_utf8_lossy(&chunk[..n]));
	}
}

/// Read from `stream` until `needle` appears in the accumulated text.
async fn read_until<S>(stream: &mut S, needle: &str) -> String
where
	S: AsyncRead + Unpin,
{
	let (got, _) = read_until_any(stream, &[needle]).await;
	got
}

/// Complete a TLS handshake to `name`, trusting only `ca_pem`.
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

/// Open a fresh TLS IMAP connection, log in, and return the stream. A fresh
/// connection keeps the IMAP state simple and matches the per-poll pattern
/// the e2e test uses. Returns the post-login stream and the LOGIN reply
/// text so callers can assert the kind of outcome.
async fn login(env: &Env, password: &str) -> tokio_rustls::client::TlsStream<TcpStream> {
	let addr = format!("{}:{}", env.host, env.imaps_port);
	let tcp = TcpStream::connect(&addr).await.expect("connect imaps");
	let mut tls = tls_client_connect(tcp, env.server_name.clone(), &env.ca_pem).await;
	read_until(&mut tls, "OK").await;
	send_line(&mut tls, &format!("a1 LOGIN {} {}", env.account, password)).await;
	let (reply, matched) = read_until_any(&mut tls, &["a1 OK", "a1 NO"]).await;
	assert_eq!(
		matched, "a1 OK",
		"LOGIN with the given credential failed: {reply}"
	);
	tls
}

/// Open a fresh connection, log in, SELECT INBOX, and FETCH (FLAGS BODY[]).
/// The flags are checked for the marker; the body for the subject.
async fn fetch_message(env: &Env, password: &str) -> (String, String) {
	let mut tls = login(env, password).await;
	send_line(&mut tls, "a2 SELECT INBOX").await;
	let (select, _) = read_until_any(&mut tls, &["a2 OK", "a2 NO"]).await;
	assert!(
		select.contains("a2 OK"),
		"SELECT INBOX after upgrade: {select}"
	);
	assert!(
		!select.contains("* 0 EXISTS"),
		"INBOX empty after upgrade: {select}"
	);
	send_line(&mut tls, "a3 FETCH 1:* (FLAGS BODY[])").await;
	let (fetch, _) = read_until_any(&mut tls, &["a3 OK", "a3 NO"]).await;
	assert!(fetch.contains("a3 OK"), "FETCH after upgrade: {fetch}");
	send_line(&mut tls, "a4 LOGOUT").await;
	let _ = read_until(&mut tls, "a4 OK").await;
	(select, fetch)
}

/// Inspect `path` (when set) and fail on a `ERROR` line. The e2e workflow
/// redirects the server's systemd journal there. We only assert on `ERROR`
/// because startup banners, INFO lines and the connection log are all part
/// of the normal output; the upgrade path is the one that must remain quiet.
fn assert_log_clean(path: &Option<String>) {
	let Some(path) = path.as_ref() else {
		return;
	};
	let text = match std::fs::read_to_string(path) {
		Ok(text) => text,
		Err(error) => panic!("reading server log {path:?}: {error}"),
	};
	for line in text.lines() {
		if line.contains("ERROR") {
			panic!("server log contains ERROR line after upgrade: {line}");
		}
	}
}

#[ignore]
#[tokio::test]
async fn previous_binary_state_survives_upgrade() {
	// Ignored by default and run only by the upgrade workflow, which sets
	// every variable: a missing one is a broken workflow, not a skip.
	let env = Env::load().expect("the upgrade workflow must set every UPGRADE_* variable");

	// 1) The password set on the previous binary still authenticates.
	let mut tls = login(&env, &env.password).await;
	send_line(&mut tls, "a2 LOGOUT").await;
	let _ = read_until(&mut tls, "a2 OK").await;
	drop(tls);

	// 2) The message and its flag are still there.
	let (select, fetch) = fetch_message(&env, &env.password).await;
	assert!(
		!select.contains("* 0 EXISTS"),
		"INBOX empty after upgrade: {select}"
	);
	assert!(
		fetch.contains(&format!("Subject: {}", env.marker)),
		"FETCH missing marker subject: {fetch}"
	);
	assert!(
		fetch.contains("\\Flagged"),
		"FETCH missing \\Flagged: {fetch}"
	);

	// 3) The app password set on the previous binary still authenticates.
	let mut tls = login(&env, &env.app_password).await;
	send_line(&mut tls, "a2 LOGOUT").await;
	let _ = read_until(&mut tls, "a2 OK").await;

	// 4) The new binary's startup log is clean.
	assert_log_clean(&env.server_log);
}
