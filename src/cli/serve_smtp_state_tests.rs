use super::*;

use crate::antispam::hook::HookVerdict;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;

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
