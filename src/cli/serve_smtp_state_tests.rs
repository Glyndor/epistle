use super::*;

use crate::antispam::hook::HookVerdict;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;

/// Build an [`ApiState`]-free [`Config`] without going through the
/// `mail.toml` validator: the tests in this file only touch the new
/// `[server] max_message_size`, `max_connections_per_ip`, and
/// `message_memory_budget` keys, which `Config::load` itself parses
/// through `#[serde(default)]`. The validator still wants the same
/// fields as the rest of the config (hostname, data_dir), so the
/// helper above is not enough on its own for everything below.
fn build_config(dir: &std::path::Path, settings: &str) -> Config {
	config(dir, settings)
}

#[test]
fn max_message_size_config_threads_through_smtp_shared_state() {
	let dir = tempfile::tempdir().expect("tempdir");
	let metrics = Arc::new(Metrics::new());
	// Absent on the config: SmtpSharedState keeps the SMTP session's
	// `0` sentinel, which the server builder turns into
	// `MAX_MESSAGE_SIZE`.
	let default = build_smtp_shared_state(&build_config(dir.path(), ""), &metrics).expect("state");
	assert_eq!(default.max_message_size, 0);
	// A positive operator value is forwarded byte-for-byte to the
	// listener's `with_max_message_size` setter.
	let set = build_smtp_shared_state(
		&build_config(dir.path(), "max_message_size = 5242880"),
		&metrics,
	)
	.expect("state");
	assert_eq!(set.max_message_size, 5 * 1024 * 1024);
}

#[test]
fn max_connections_per_ip_config_threads_through_smtp_shared_state() {
	let dir = tempfile::tempdir().expect("tempdir");
	let metrics = Arc::new(Metrics::new());
	// Absent on the config: the helper promotes the operator's `0` to
	// the SMTP listener's built-in default so a configured zero (or no
	// entry at all) means "use the protocol default", never "0
	// concurrent connections per peer".
	let default = build_smtp_shared_state(&build_config(dir.path(), ""), &metrics).expect("state");
	assert_eq!(
		default.max_connections_per_ip,
		crate::smtp::server::DEFAULT_MAX_CONNECTIONS_PER_IP,
		"absent falls back to the listener's built-in default"
	);
	// A positive operator value is forwarded byte-for-byte.
	let set = build_smtp_shared_state(
		&build_config(dir.path(), "max_connections_per_ip = 7"),
		&metrics,
	)
	.expect("state");
	assert_eq!(set.max_connections_per_ip, 7);
}

#[test]
fn message_memory_budget_config_threads_through_smtp_shared_state() {
	let dir = tempfile::tempdir().expect("tempdir");
	let metrics = Arc::new(Metrics::new());
	// `Some(0)` keeps the historical unbounded behaviour: the budget
	// slot stays `None`, no reservation can ever fail.
	let zero = build_smtp_shared_state(
		&build_config(dir.path(), "message_memory_budget = 0"),
		&metrics,
	)
	.expect("state");
	assert!(
		zero.memory_budget.is_none(),
		"message_memory_budget = 0 must disable the budget"
	);
	// Any other value produces a budget with the matching cap. The
	// shared `Arc<MemoryBudget>` is the same handle every SMTP listener
	// will receive.
	let set = build_smtp_shared_state(
		&build_config(dir.path(), "message_memory_budget = 134217728"),
		&metrics,
	)
	.expect("state");
	let budget = set.memory_budget.as_ref().expect("budget present");
	assert_eq!(budget.cap(), 128 * 1024 * 1024);
}

fn config(dir: &std::path::Path, settings: &str) -> Config {
	toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = '{}'\n{settings}",
		dir.display()
	))
	.expect("config")
}

#[test]
fn scanner_selection_preserves_http_and_disabled_modes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let metrics = Arc::new(Metrics::new());
	let disabled = build_smtp_shared_state(&config(dir.path(), ""), &metrics).expect("state");
	assert!(disabled.scanner_hook.is_none());
	let http = build_smtp_shared_state(
		&config(
			dir.path(),
			"scanner_hook_url = 'http://scanner.example/scan'",
		),
		&metrics,
	)
	.expect("state");
	assert!(http.scanner_hook.is_some());
}

#[tokio::test]
async fn clamd_startup_applies_action_size_and_shared_metrics() {
	let dir = tempfile::tempdir().expect("tempdir");
	let socket = dir.path().join("clamd.sock");
	let listener = UnixListener::bind(&socket).expect("bind");
	let task = tokio::spawn(async move {
		let (mut stream, _) = listener.accept().await.expect("accept");
		let mut request = [0; 21];
		stream.read_exact(&mut request).await.expect("request");
		stream
			.write_all(b"stream: Eicar-Test-Signature FOUND\0")
			.await
			.expect("reply");
	});
	let config = config(
		dir.path(),
		&format!(
			"[antispam]\nclamd_socket = '{}'\nclamd_on_found = 'reject'\nclamd_max_bytes = 3",
			socket.display()
		),
	);
	let metrics = Arc::new(Metrics::new());
	let state = build_smtp_shared_state(&config, &metrics).expect("state");
	let hook = state.scanner_hook.expect("clamd enabled");
	let verdict = tokio::time::timeout(Duration::from_secs(2), hook.scan(b"msg"))
		.await
		.expect("deadline");
	assert_eq!(verdict, HookVerdict::Reject);
	task.await.expect("fake");
	assert_eq!(hook.scan(b"long").await, HookVerdict::Accept);
	assert_eq!(metrics.snapshot().get("scanner_clamd_skipped"), Some(&1));
	assert_eq!(hook.scan(b"msg").await, HookVerdict::Accept);
	assert_eq!(metrics.snapshot().get("scanner_clamd_failed"), Some(&1));
}

#[tokio::test]
async fn clamd_startup_applies_configured_timeout() {
	let dir = tempfile::tempdir().expect("tempdir");
	let socket = dir.path().join("clamd.sock");
	let listener = UnixListener::bind(&socket).expect("bind");
	let task = tokio::spawn(async move {
		let (mut stream, _) = listener.accept().await.expect("accept");
		let mut bytes = Vec::new();
		stream
			.read_to_end(&mut bytes)
			.await
			.expect("read until timeout");
		bytes
	});
	let config = config(
		dir.path(),
		&format!(
			"[antispam]\nclamd_socket = '{}'\nclamd_timeout_secs = 1",
			socket.display()
		),
	);
	let metrics = Arc::new(Metrics::new());
	let state = build_smtp_shared_state(&config, &metrics).expect("state");
	let hook = state.scanner_hook.expect("clamd enabled");
	let started = std::time::Instant::now();
	let verdict = tokio::time::timeout(Duration::from_secs(2), hook.scan(b"msg"))
		.await
		.expect("configured deadline");
	assert_eq!(verdict, HookVerdict::Accept);
	assert!(
		started.elapsed() >= Duration::from_millis(900),
		"deadline fired early"
	);
	assert_eq!(metrics.snapshot().get("scanner_clamd_failed"), Some(&1));
	assert!(task.await.expect("peer").starts_with(b"zINSTREAM\0"));
}
