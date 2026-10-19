//! `serve` hands the connection caps of the configuration to every listener
//! that has one: the unit tests of each server cannot see a cap that the
//! wiring forgot to pass on.

use super::*;
use std::path::Path;
use std::time::Duration;

use crate::config::Listener;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

fn config(dir: &Path, listeners: &[(&str, u16)], settings: &str) -> Config {
	let mut config: Config = toml::from_str(&format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\n{settings}\n",
		dir.join("data").display()
	))
	.expect("config");
	let cert = rcgen::generate_simple_self_signed(vec!["mail.example.org".into()]).expect("cert");
	let tls = crate::config::Tls {
		cert_file: dir.join("cert.pem"),
		key_file: dir.join("key.pem"),
		client_ca: None,
	};
	std::fs::write(&tls.cert_file, cert.cert.pem()).expect("cert file");
	std::fs::write(&tls.key_file, cert.signing_key.serialize_pem()).expect("key file");
	{
		use std::os::unix::fs::PermissionsExt;
		std::fs::set_permissions(&tls.key_file, std::fs::Permissions::from_mode(0o600))
			.expect("key mode");
	}
	config.tls = Some(tls);
	config.listeners = listeners
		.iter()
		.map(|(kind, port)| -> Listener {
			toml::from_str(&format!(
				"kind = \"{kind}\"\naddr = \"127.0.0.1\"\nport = {port}"
			))
			.expect("listener")
		})
		.collect();
	config
}

/// Connect (the listener may still be binding) and return the connection
/// with whatever the server said first, if it said anything.
async fn attempt(port: u16) -> (TcpStream, String) {
	let mut stream = None;
	for _ in 0..200 {
		if let Ok(connected) = TcpStream::connect(("127.0.0.1", port)).await {
			stream = Some(connected);
			break;
		}
		tokio::time::sleep(Duration::from_millis(40)).await;
	}
	let mut stream = stream.expect("the listener came up");
	let mut buf = [0u8; 512];
	let said = tokio::time::timeout(Duration::from_millis(150), stream.read(&mut buf)).await;
	let text = match said {
		Ok(Ok(n)) => String::from_utf8_lossy(&buf[..n]).into_owned(),
		_ => String::new(),
	};
	(stream, text)
}

/// Connect to `port` and return the stream without reading from it.
/// Retries while the listener is binding so a cold test does not race
/// the server.
async fn connect_only(port: u16) -> TcpStream {
	let mut stream = None;
	for _ in 0..200 {
		if let Ok(connected) = TcpStream::connect(("127.0.0.1", port)).await {
			stream = Some(connected);
			break;
		}
		tokio::time::sleep(Duration::from_millis(40)).await;
	}
	stream.expect("the listener came up")
}

/// Open three connections in a row; the first two must be admitted and the
/// third must be refused with `expected`.
///
/// All three connections are kept open at once, so the server-side admit
/// guard is still held for the first two when the third arrives. The
/// server checks admission synchronously after the TCP accept, so by the
/// time the third `connect()` returns the refusal has already been
/// written and the stream is half-closed on the server side. The first
/// two are then probed with a real request to prove they were admitted
/// (not merely left open): an admitted HTTP connection answers the
/// probe with a non-503 status line, an admitted mailbox connection
/// answers the probe with the protocol's greeting (which the refusal
/// never sends).
async fn third_is_refused(name: &str, port: u16, expected: &str) {
	let is_http = expected.contains("HTTP/");
	let mut streams = Vec::with_capacity(3);
	for _ in 0..3 {
		streams.push(connect_only(port).await);
	}
	let mut said = Vec::with_capacity(3);
	for mut stream in streams.drain(..) {
		if is_http {
			use tokio::io::{AsyncReadExt, AsyncWriteExt};
			let _ = stream
				.write_all(b"GET /probe HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
				.await;
			let mut buf = Vec::new();
			let _ = tokio::time::timeout(Duration::from_millis(500), stream.read_to_end(&mut buf))
				.await;
			said.push(String::from_utf8_lossy(&buf).into_owned());
		} else {
			use tokio::io::AsyncReadExt;
			let mut buf = Vec::new();
			let _ = tokio::time::timeout(Duration::from_millis(500), stream.read_to_end(&mut buf))
				.await;
			said.push(String::from_utf8_lossy(&buf).into_owned());
		}
	}
	// The first two connections must not be refused. The mailbox
	// refusals all carry "too many"; the plain-HTTP refusal starts with
	// `HTTP/1.1 503` and contains `Service Unavailable`. An admitted
	// HTTP connection returns a status line that does NOT start with
	// `HTTP/1.1 503`; an admitted mailbox connection returns the
	// protocol's success greeting, not the BYE/-ERR refusal.
	if is_http {
		assert!(
			said[0].starts_with("HTTP/1.1 ") && !said[0].starts_with("HTTP/1.1 503"),
			"{name}: the first connection must be admitted, not refused: {said:?}"
		);
		assert!(
			said[1].starts_with("HTTP/1.1 ") && !said[1].starts_with("HTTP/1.1 503"),
			"{name}: the second connection must be admitted, not refused: {said:?}"
		);
	} else {
		assert!(
			!said[0].contains("too many") && !said[1].contains("too many"),
			"{name}: the first two connections must be admitted: {said:?}"
		);
	}
	assert!(
		said[2].contains(expected),
		"{name}: the third connection must get {expected:?}: {said:?}"
	);
}

#[tokio::test]
async fn serve_applies_the_client_caps_to_every_listener() {
	let dir = tempfile::tempdir().expect("tempdir");
	let ports: Vec<u16> = (0..5).map(|_| crate::test_fixtures::free_port()).collect();
	let listeners = [
		("imap", ports[0]),
		("pop3s", ports[1]),
		("manage-sieve", ports[2]),
		("acme", ports[3]),
		("metrics", ports[4]),
	];
	let settings = "max_mailbox_connections_per_ip = 2\nmax_http_connections_per_ip = 2";
	let server = tokio::spawn(serve(config(dir.path(), &listeners, settings)));
	third_is_refused(
		"imap",
		ports[0],
		"* BYE too many connections from your address",
	)
	.await;
	third_is_refused(
		"pop3s",
		ports[1],
		"-ERR too many connections from your address",
	)
	.await;
	third_is_refused(
		"manage-sieve",
		ports[2],
		"BYE \"too many connections from your address\"",
	)
	.await;
	third_is_refused("acme", ports[3], "HTTP/1.1 503 Service Unavailable").await;
	third_is_refused("metrics", ports[4], "HTTP/1.1 503 Service Unavailable").await;
	server.abort();
}

#[tokio::test]
async fn serve_applies_the_http_listener_cap() {
	let dir = tempfile::tempdir().expect("tempdir");
	let port = crate::test_fixtures::free_port();
	let settings = "max_http_connections = 2";
	let server = tokio::spawn(serve(config(dir.path(), &[("metrics", port)], settings)));
	third_is_refused("metrics", port, "HTTP/1.1 503 Service Unavailable").await;
	server.abort();
}

#[tokio::test]
async fn serve_applies_the_http_caps_to_api_webdav_and_autoconfig() {
	let dir = tempfile::tempdir().expect("tempdir");
	let ports: Vec<u16> = (0..3).map(|_| crate::test_fixtures::free_port()).collect();
	let listeners = [
		("api", ports[0]),
		("web-dav", ports[1]),
		("autoconfig", ports[2]),
	];
	let hash = format!("sha256:{}", "ab".repeat(32));
	let settings = format!("max_http_connections_per_ip = 2\n[api]\ntoken_hash = \"{hash}\"");
	let server = tokio::spawn(serve(config(dir.path(), &listeners, &settings)));
	third_is_refused("api", ports[0], "HTTP/1.1 503 Service Unavailable").await;
	third_is_refused("web-dav", ports[1], "HTTP/1.1 503 Service Unavailable").await;
	third_is_refused("autoconfig", ports[2], "HTTP/1.1 503 Service Unavailable").await;
	server.abort();
}

#[tokio::test]
async fn serve_applies_the_managesieve_default_of_40() {
	let dir = tempfile::tempdir().expect("tempdir");
	let port = crate::test_fixtures::free_port();
	let server = tokio::spawn(serve(config(dir.path(), &[("manage-sieve", port)], "")));
	let mut kept = Vec::new();
	let mut last = String::new();
	for i in 0..41 {
		let (s, said) = attempt(port).await;
		kept.push(s);
		if i == 39 {
			assert!(!said.contains("too many"), "40th refused: {said}");
		}
		last = said;
	}
	assert!(
		last.contains("too many connections from your address"),
		"41st: {last}"
	);
	server.abort();
}

/// The `max_http_connections_per_ip` row of `docs/configuration.md` must
/// describe the cap the same way the server applies it: the listener
/// list includes the autoconfig listener over HTTPS and MTA-STS, the
/// count uses the TCP peer address (no forwarded headers), and an IPv6
/// client is counted by its /64. Operators planning a proxy in front
/// of the listener need the proxy-effect note to size the cap right.
/// Each phrase is one sentence the reviewer of the previous PR said
/// was missing from the docs; removing any of them breaks the
/// corresponding behaviour claim, and the test fails before the fix
/// lands.
#[test]
fn max_http_connections_per_ip_doc_describes_tls_and_proxy_effect() {
	const DOC: &str = include_str!("../../docs/configuration.md");
	let row_start = DOC
		.find("| `max_http_connections_per_ip` |")
		.expect("docs row present");
	let next_row = DOC[row_start..]
		.find("\n| `queue_give_up_secs`")
		.expect("next row anchor present");
	let row_end = row_start + next_row;
	let row = &DOC[row_start..row_end];
	for phrase in [
		"autoconfig over HTTPS",
		"MTA-STS",
		"closed before any TLS handshake",
		"TCP peer address from the socket",
		"X-Forwarded-For",
		"`[api].trusted_proxies` does not affect it",
		"IPv6 client is counted by its /64",
		"IPv4-mapped address as the IPv4 address",
		"behind a proxy every connection looks like the proxy",
	] {
		assert!(
			row.contains(phrase),
			"docs row for max_http_connections_per_ip is missing {phrase:?}\n--- row ---\n{row}\n---"
		);
	}
}
