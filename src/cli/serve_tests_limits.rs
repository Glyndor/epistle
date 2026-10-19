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

/// Open three connections in a row; the first two must be admitted and the
/// third must be refused with `expected`.
async fn third_is_refused(name: &str, port: u16, expected: &str) {
	let mut kept = Vec::new();
	let mut said = Vec::new();
	for _ in 0..3 {
		let (stream, text) = attempt(port).await;
		kept.push(stream);
		said.push(text);
	}
	assert!(
		!said[0].contains("too many") && !said[1].contains("too many"),
		"{name}: the first two connections must be admitted: {said:?}"
	);
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
