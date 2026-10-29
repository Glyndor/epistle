//! Tests for the `probe` subcommand.
//!
//! Drives the probe against real TCP listeners bound on `127.0.0.1:0`.
//! Each test owns a tiny accept loop that hands the client the
//! protocol's greeting then closes the connection; we are not testing
//! any specific server implementation, only that the probe speaks the
//! right wire against an answering peer. A second set of tests uses a
//! closed port to drive the failure path.

use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

use serde_json::Value;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use super::probe_all;
use crate::config::{Config, Listener, ListenerKind};

/// A greeting a test server can hand back to the probe.
const SMTP_BANNER: &[u8] = b"220 mail.example.org ESMTP\r\n";
const IMAP_GREETING: &[u8] = b"* OK [CAPABILITY IMAP4rev1] mail.example.org ready.\r\n";
const HTTP_OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// Build a `Config` whose listener set is exactly what the test asked
/// for, with bind on loopback. The data_dir and hostname are present
/// because `Config::load` and the renderer both want them, even though
/// `probe::run` only reads `listeners`.
fn config_with(listeners: Vec<Listener>) -> Config {
	let dir = tempfile::tempdir().expect("tempdir");
	let toml = format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\n",
		dir.path().display()
	);
	let mut config: Config = toml::from_str(&toml).expect("base config");
	config.listeners = listeners;
	let _ = Path::new(""); // silence unused-import lint when data_dir is referenced via display()
	config
}

/// Build a `Listener` of `kind` bound to a TCP listener that the
/// caller will accept on. Returns the parsed listener (with the
/// kernel-picked port) plus the live `TcpListener` plus a kill switch
/// that aborts the accept loop when dropped.
async fn live_listener(kind: ListenerKind) -> (Listener, TcpListener, Option<oneshot::Sender<()>>) {
	let listener = TcpListener::bind((IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
		.await
		.expect("bind");
	let port = listener.local_addr().expect("addr").port();
	let kind_str = kind.as_str();
	let config_toml = format!("kind = \"{kind_str}\"\naddr = \"127.0.0.1\"\nport = {port}\n");
	let parsed: Listener = toml::from_str(&config_toml).expect("listener parses");
	(parsed, listener, None)
}

/// Stub accept loop: write the configured reply once, then drop the
/// connection. Returning quickly keeps each probe well inside the
/// 2-second window the production code allows.
async fn accept_one(listener: TcpListener, reply: &'static [u8]) {
	if let Ok((mut socket, _)) = listener.accept().await {
		let _ = socket.write_all(reply).await;
		let _ = socket.shutdown().await;
	}
}

/// Spawn the stub accept loop and let it run to completion. Holding
/// the `JoinHandle` lets the caller `abort()` it on shutdown.
fn spawn_reply(listener: TcpListener, reply: &'static [u8]) -> tokio::task::JoinHandle<()> {
	tokio::spawn(accept_one(listener, reply))
}

#[tokio::test]
async fn probe_returns_ok_line_for_a_listening_smtp_listener() {
	let (listener, server, _) = live_listener(ListenerKind::Smtp).await;
	let handle = spawn_reply(server, SMTP_BANNER);
	let config = config_with(vec![listener]);
	let results = probe_all(&config.listeners, None).await.expect("probe");
	assert_eq!(results.len(), 1);
	let line = &results[0];
	assert_eq!(line.kind, "smtp");
	assert!(
		line.addr.starts_with("127.0.0.1:"),
		"loopback addr: {}",
		line.addr
	);
	assert!(line.ok, "{:?}", line.error);
	let _ = handle.await;
}

#[tokio::test]
async fn probe_returns_fail_line_for_a_closed_port_with_actionable_reason() {
	// Pick a port that is almost certainly closed: bind, drop, so the
	// kernel is not actively listening. The probe must reach the
	// "connect refused" branch and surface it on the failure line.
	let probe_socket = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
	let port = probe_socket.local_addr().expect("addr").port();
	drop(probe_socket);
	let listener: Listener = toml::from_str(&format!(
		"kind = \"smtp\"\naddr = \"127.0.0.1\"\nport = {port}\n"
	))
	.expect("listener");
	let config = config_with(vec![listener]);
	let results = probe_all(&config.listeners, None).await.expect("probe");
	assert_eq!(results.len(), 1);
	let line = &results[0];
	assert!(!line.ok, "closed port must fail: {:?}", line);
	assert!(
		line.error.as_deref().unwrap_or("").contains("connect"),
		"failure must carry a connect reason: {:?}",
		line.error
	);
	assert!(
		line.addr.ends_with(&format!(":{port}")),
		"failure must report the dialed addr: {:?}",
		line.addr
	);
}

#[tokio::test]
async fn probe_classifies_three_protocols_in_one_run() {
	// One listener per family: SMTP (plaintext banner), HTTP HEAD,
	// IMAP greeting. Three different accept loops, all on the same
	// tokio runtime. Asserts the kind strings, that all three report
	// ok, and that the order matches the config.
	let (smtp, smtp_socket, _) = live_listener(ListenerKind::Smtp).await;
	let (api, api_socket, _) = live_listener(ListenerKind::Api).await;
	let (imap, imap_socket, _) = live_listener(ListenerKind::Imap).await;
	let h_smtp = spawn_reply(smtp_socket, SMTP_BANNER);
	let h_api = spawn_reply(api_socket, HTTP_OK);
	let h_imap = spawn_reply(imap_socket, IMAP_GREETING);
	let config = config_with(vec![smtp, api, imap]);
	let results = probe_all(&config.listeners, None).await.expect("probe");
	assert_eq!(results.len(), 3);
	let kinds: Vec<_> = results.iter().map(|r| r.kind).collect();
	assert_eq!(kinds, vec!["smtp", "api", "imap"]);
	for line in &results {
		assert!(line.ok, "{}: {:?}", line.kind, line.error);
	}
	for h in [h_smtp, h_api, h_imap] {
		let _ = h.await;
	}
}

#[tokio::test]
async fn probe_marks_failed_listener_without_short_circuiting() {
	// One listener answers, the other one has nothing listening.
	// The well-behaved one must still come back `ok` even though a
	// sibling listener is down — the healthcheck is per-listener, not
	// global.
	let (smtp, smtp_socket, _) = live_listener(ListenerKind::Smtp).await;
	let probe_socket = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
	let dead_port = probe_socket.local_addr().expect("addr").port();
	drop(probe_socket);
	let dead: Listener = toml::from_str(&format!(
		"kind = \"imap\"\naddr = \"127.0.0.1\"\nport = {dead_port}\n"
	))
	.expect("listener");
	let h_smtp = spawn_reply(smtp_socket, SMTP_BANNER);
	let config = config_with(vec![smtp, dead]);
	let results = probe_all(&config.listeners, None).await.expect("probe");
	assert_eq!(results.len(), 2);
	assert!(results[0].ok, "smtp ok: {:?}", results[0].error);
	assert!(!results[1].ok, "closed imap must fail: {:?}", results[1]);
	assert_eq!(results[1].kind, "imap");
	let _ = h_smtp.await;
}

#[tokio::test]
async fn probe_rejects_a_non_smtp_banner_with_a_descriptive_error() {
	// The probe connects, gets bytes, but they're not a 220 banner. It
	// must classify that as a failure with the actual banner in the
	// reason (for an operator chasing a misrouted port).
	let (listener, server, _) = live_listener(ListenerKind::Smtp).await;
	let handle = spawn_reply(server, b"421 service not available\r\n");
	let config = config_with(vec![listener]);
	let results = probe_all(&config.listeners, None).await.expect("probe");
	let line = &results[0];
	assert!(!line.ok, "non-220 banner must fail: {line:?}");
	assert!(
		line.error
			.as_deref()
			.unwrap_or("")
			.contains("expected SMTP 220 banner"),
		"reason: {:?}",
		line.error
	);
	let _ = handle.await;
}

#[tokio::test]
async fn probe_verifies_loopback_substitution_for_unspecified_bind_address() {
	// A listener configured with `addr = "0.0.0.0"` must be probed on
	// 127.0.0.1, not on 0.0.0.0 directly. The kernel will silently
	// route that to a wrong peer on a multi-homed host, so check the
	// `loopback_for` substitution explicitly.
	let listener = TcpListener::bind((IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
		.await
		.expect("bind");
	let port = listener.local_addr().expect("addr").port();
	let handle = spawn_reply(listener, SMTP_BANNER);
	// `addr = "0.0.0.0"` is the path the operator types when the
	// listener is expected to accept on any interface. The probe must
	// convert that to `127.0.0.1` for the loopback dial.
	let listener: Listener = toml::from_str(&format!(
		"kind = \"smtp\"\naddr = \"0.0.0.0\"\nport = {port}\n"
	))
	.expect("listener parses");
	let config = config_with(vec![listener]);
	let results = probe_all(&config.listeners, None).await.expect("probe");
	let line = &results[0];
	assert!(line.ok, "0.0.0.0 listener probed on loopback: {line:?}");
	assert_eq!(
		line.addr,
		format!("127.0.0.1:{port}"),
		"the probe addr must be loopback, not 0.0.0.0"
	);
	let _ = handle.await;
}

#[tokio::test]
async fn probe_produces_the_json_shape_when_run_with_json() {
	let (smtp, smtp_socket, _) = live_listener(ListenerKind::Smtp).await;
	let handle = spawn_reply(smtp_socket, SMTP_BANNER);
	let config = config_with(vec![smtp]);
	let results = probe_all(&config.listeners, None).await.expect("probe");
	let bytes = serde_json::to_string(&results).expect("serialise");
	let parsed: Vec<Value> = serde_json::from_str(&bytes).expect("parse");
	assert_eq!(parsed.len(), 1);
	let entry = &parsed[0];
	assert_eq!(entry["kind"], "smtp");
	assert_eq!(entry["ok"], true);
	// `error` is `skip_serializing_if = "Option::is_none"`; the JSON
	// shape must omit it on success, not include a null.
	assert!(
		entry.get("error").is_none(),
		"successful probe entry must omit `error`; got {entry}"
	);
	let _ = handle.await;
}

#[tokio::test]
async fn probe_accepts_a_wrong_protocol_on_the_same_port() {
	// Configure the probe as if it were dialling an SMTP listener,
	// but reply with HTTP. The classifier must reject the bytes and
	// the error reason must carry the observed banner — losing the
	// banner would make "wrong service on this port" hard to debug.
	let (listener, server, _) = live_listener(ListenerKind::Smtp).await;
	let handle = spawn_reply(server, HTTP_OK);
	let config = config_with(vec![listener]);
	let results = probe_all(&config.listeners, None).await.expect("probe");
	let line = &results[0];
	assert!(!line.ok, "HTTP on SMTP port must fail: {line:?}");
	assert!(
		line.error
			.as_deref()
			.unwrap_or("")
			.contains("expected SMTP 220 banner"),
		"reason: {:?}",
		line.error
	);
	assert!(
		line.error.as_deref().unwrap_or("").contains("HTTP/"),
		"reason must surface the observed banner; got {:?}",
		line.error
	);
	let _ = handle.await;
}

#[tokio::test]
async fn empty_listener_set_yields_empty_results_and_callers_see_success() {
	// A config with no listeners is not an error: `epistle probe`
	// succeeds when there is nothing to probe.
	let config = config_with(vec![]);
	let results = probe_all(&config.listeners, None).await.expect("probe");
	assert!(results.is_empty());
}
