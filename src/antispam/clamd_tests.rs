use super::*;

use std::sync::Mutex;

use tokio::net::UnixListener;
use tokio::sync::oneshot;
use tracing_subscriber::layer::SubscriberExt;

struct FakeClamd {
	_dir: tempfile::TempDir,
	socket: PathBuf,
	stop: oneshot::Sender<()>,
	task: tokio::task::JoinHandle<Vec<u8>>,
}

impl FakeClamd {
	fn start(payload_bytes: usize, reply: &'static [u8]) -> Self {
		let dir = tempfile::tempdir().expect("tempdir");
		let socket = dir.path().join("clamd.sock");
		let listener = UnixListener::bind(&socket).expect("bind fake clamd");
		let (stop, stopped) = oneshot::channel();
		let task = tokio::spawn(async move {
			let (mut stream, _) = tokio::select! {
				biased;
				connection = listener.accept() => connection.expect("accept"),
				_ = stopped => return Vec::new(),
			};
			let mut wire = vec![0; 10 + payload_bytes + payload_bytes.div_ceil(65536) * 4 + 4];
			stream.read_exact(&mut wire).await.expect("read request");
			stream.write_all(reply).await.expect("write reply");
			wire
		});
		Self {
			_dir: dir,
			socket,
			stop,
			task,
		}
	}

	async fn finish(self) -> Vec<u8> {
		let _ = self.stop.send(());
		tokio::time::timeout(Duration::from_secs(2), self.task)
			.await
			.expect("fake completed")
			.expect("fake task")
	}
}

async fn scan(hook: &dyn MailHook, raw: &[u8]) -> HookVerdict {
	tokio::time::timeout(Duration::from_secs(2), hook.scan(raw))
		.await
		.expect("scan exceeded test deadline")
}

fn assert_counters(metrics: &Metrics, failed: u64, skipped: u64) {
	let snapshot = metrics.snapshot();
	assert_eq!(snapshot.get("scanner_clamd_failed"), Some(&failed));
	assert_eq!(snapshot.get("scanner_clamd_skipped"), Some(&skipped));
}

#[tokio::test]
async fn instream_records_big_endian_chunks_and_exact_payload() {
	let raw: Vec<u8> = (0..200 * 1024).map(|i| (i % 251) as u8).collect();
	let fake = FakeClamd::start(raw.len(), b"stream: OK\0");
	let hook = ClamdHook::new(fake.socket.clone());
	assert_eq!(scan(&hook, &raw).await, HookVerdict::Accept);
	let wire = fake.finish().await;
	assert!(wire.starts_with(b"zINSTREAM\0"));
	let mut rest = &wire[10..];
	let mut payload = Vec::new();
	for expected_len in [65536, 65536, 65536, 8192] {
		let length = u32::from_be_bytes(rest[..4].try_into().expect("header")) as usize;
		assert_eq!(length, expected_len, "big-endian chunk length");
		payload.extend_from_slice(&rest[4..4 + length]);
		rest = &rest[4 + length..];
	}
	assert_eq!(rest, &[0; 4], "zero-length terminator");
	assert!(payload == raw, "payload changed during framing");
}

#[tokio::test]
async fn replies_select_verdict_and_count_errors() {
	for (reply, action, expected, failed) in [
		(
			b"stream: OK\0".as_slice(),
			HookVerdict::Quarantine,
			HookVerdict::Accept,
			0,
		),
		(
			b"stream: Eicar-Test-Signature FOUND\0",
			HookVerdict::Quarantine,
			HookVerdict::Quarantine,
			0,
		),
		(
			b"stream: Eicar-Test-Signature FOUND\0",
			HookVerdict::Reject,
			HookVerdict::Reject,
			0,
		),
		(
			b"INSTREAM size limit exceeded. ERROR\0",
			HookVerdict::Reject,
			HookVerdict::Accept,
			1,
		),
		(
			b"stream: scan failed ERROR\0",
			HookVerdict::Reject,
			HookVerdict::Accept,
			1,
		),
		(
			b"unknown reply\0",
			HookVerdict::Reject,
			HookVerdict::Accept,
			1,
		),
		(
			b"stream: FOUND\0",
			HookVerdict::Reject,
			HookVerdict::Accept,
			1,
		),
		(
			b"stream:  FOUND\0",
			HookVerdict::Reject,
			HookVerdict::Accept,
			1,
		),
		(
			b"stream: bad\nname FOUND\0",
			HookVerdict::Reject,
			HookVerdict::Accept,
			1,
		),
		(
			b"stream: \xff FOUND\0",
			HookVerdict::Reject,
			HookVerdict::Accept,
			1,
		),
		(b"stream: OK", HookVerdict::Reject, HookVerdict::Accept, 1),
		(b"", HookVerdict::Reject, HookVerdict::Accept, 1),
	] {
		let fake = FakeClamd::start(3, reply);
		let metrics = Arc::new(Metrics::new());
		let hook = ClamdHook::new(fake.socket.clone())
			.with_on_found(action)
			.with_metrics(metrics.clone());
		assert_eq!(scan(&hook, b"msg").await, expected, "reply verdict");
		assert_counters(&metrics, failed, 0);
		assert!(!fake.finish().await.is_empty());
	}
}

#[tokio::test]
async fn missing_socket_fails_open_immediately() {
	let dir = tempfile::tempdir().expect("tempdir");
	let socket = dir.path().join("clamd.sock");
	assert!(!socket.exists());
	let metrics = Arc::new(Metrics::new());
	let hook = ClamdHook::new(socket).with_metrics(metrics.clone());
	let started = Instant::now();
	assert_eq!(scan(&hook, b"msg").await, HookVerdict::Accept);
	assert!(
		started.elapsed() < Duration::from_secs(1),
		"socket failure was delayed"
	);
	assert_counters(&metrics, 1, 0);
}

#[tokio::test]
async fn refused_socket_fails_open_immediately() {
	let dir = tempfile::tempdir().expect("tempdir");
	let socket = dir.path().join("clamd.sock");
	drop(UnixListener::bind(&socket).expect("bind stale socket"));
	let metrics = Arc::new(Metrics::new());
	let hook = ClamdHook::new(socket).with_metrics(metrics.clone());
	let started = Instant::now();
	assert_eq!(scan(&hook, b"msg").await, HookVerdict::Accept);
	assert!(
		started.elapsed() < Duration::from_secs(1),
		"socket failure was delayed"
	);
	assert_counters(&metrics, 1, 0);
}

#[tokio::test]
async fn silent_peer_times_out_after_200_ms() {
	let dir = tempfile::tempdir().expect("tempdir");
	let socket = dir.path().join("clamd.sock");
	let listener = UnixListener::bind(&socket).expect("bind");
	let task = tokio::spawn(async move {
		let (mut stream, _) = listener.accept().await.expect("accept");
		let mut received = Vec::new();
		stream
			.read_to_end(&mut received)
			.await
			.expect("read until client closes");
		received
	});
	let metrics = Arc::new(Metrics::new());
	let hook = ClamdHook::new(socket)
		.with_timeout(Duration::from_millis(200))
		.with_metrics(metrics.clone());
	let started = Instant::now();
	assert_eq!(scan(&hook, b"msg").await, HookVerdict::Accept);
	let elapsed = started.elapsed();
	assert!(
		elapsed >= Duration::from_millis(180),
		"timeout fired too early"
	);
	assert!(elapsed < Duration::from_secs(1), "timeout fired too late");
	assert_counters(&metrics, 1, 0);
	assert!(task.await.expect("silent peer").starts_with(b"zINSTREAM\0"));
}

#[tokio::test]
async fn oversize_skips_socket_but_exact_limit_is_scanned() {
	for size in [4, 5] {
		let fake = FakeClamd::start(size, b"stream: Eicar-Test-Signature FOUND\0");
		let metrics = Arc::new(Metrics::new());
		let hook = ClamdHook::new(fake.socket.clone())
			.with_max_bytes(4)
			.with_metrics(metrics.clone());
		let verdict = scan(&hook, &vec![b'a'; size]).await;
		let wire = fake.finish().await;
		if size == 4 {
			assert_eq!(verdict, HookVerdict::Quarantine);
			assert!(!wire.is_empty(), "limit-sized message was not scanned");
			assert_counters(&metrics, 0, 0);
		} else {
			assert_eq!(verdict, HookVerdict::Accept);
			assert!(wire.is_empty(), "oversize message reached socket");
			assert_counters(&metrics, 0, 1);
		}
	}
}

#[derive(Clone, Default)]
struct Warnings(Arc<Mutex<Vec<String>>>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Warnings {
	fn on_event(
		&self,
		event: &tracing::Event<'_>,
		_ctx: tracing_subscriber::layer::Context<'_, S>,
	) {
		if *event.metadata().level() == tracing::Level::WARN {
			let mut fields = String::new();
			event.record(
				&mut |field: &tracing::field::Field, value: &dyn std::fmt::Debug| {
					use std::fmt::Write;
					write!(&mut fields, "{field}={value:?};").expect("format fields");
				},
			);
			self.0.lock().expect("warnings").push(fields);
		}
	}
}

#[test]
fn fifty_failures_warn_once_per_minute_with_injected_clock() {
	let warnings = Warnings::default();
	let subscriber = tracing_subscriber::registry().with(warnings.clone());
	let metrics = Arc::new(Metrics::new());
	let hook = ClamdHook::new(PathBuf::from("unused.sock")).with_metrics(metrics.clone());
	tracing::subscriber::with_default(subscriber, || {
		for _ in 0..50 {
			assert_eq!(
				hook.failed(&"unavailable", Duration::ZERO),
				HookVerdict::Accept
			);
		}
		assert_eq!(warnings.0.lock().expect("warnings").len(), 1);
		assert_counters(&metrics, 50, 0);
		hook.failed(&"unavailable", Duration::from_secs(59));
		assert_eq!(warnings.0.lock().expect("warnings").len(), 1);
		hook.failed(&"unavailable", Duration::from_secs(60));
		assert_eq!(warnings.0.lock().expect("warnings").len(), 2);
	});
}

#[tokio::test(flavor = "multi_thread")]
async fn detection_logs_signature_and_size_without_message() {
	let raw = uuid::Uuid::now_v7().simple().to_string();
	let warnings = Warnings::default();
	let events = warnings.0.clone();
	let subscriber = tracing_subscriber::registry().with(warnings);
	// `with_subscriber` would scope the dispatcher to one future's polling
	// and drop the warn that this test pins when the warn fires from a path
	// the wrapper does not cover. Set the dispatcher for the entire test
	// body via `block_in_place` + `Handle::block_on`, the same pattern used
	// in `crate::api::audit_tests::run_with_capture`, so the warn is
	// captured regardless of which thread the polling lands on.
	tokio::task::block_in_place(|| {
		tracing::subscriber::with_default(subscriber, || {
			tokio::runtime::Handle::current().block_on(async {
				let fake = FakeClamd::start(raw.len(), b"stream: Eicar-Test-Signature FOUND\0");
				let hook = ClamdHook::new(fake.socket.clone());
				assert_eq!(scan(&hook, raw.as_bytes()).await, HookVerdict::Quarantine);
				assert!(!fake.finish().await.is_empty());
			});
		});
	});
	let captured = events.lock().expect("warnings");
	assert_eq!(captured.len(), 1);
	assert!(captured[0].contains("signature=\"Eicar-Test-Signature\""));
	assert!(captured[0].contains(&format!("message_bytes={}", raw.len())));
	assert!(
		!captured[0].contains(&raw),
		"message content appeared in log"
	);
}

#[tokio::test]
async fn reply_limit_fails_open_and_accepts_the_boundary() {
	for length in [MAX_REPLY_BYTES, MAX_REPLY_BYTES + 1] {
		let dir = tempfile::tempdir().expect("tempdir");
		let socket = dir.path().join("clamd.sock");
		let listener = UnixListener::bind(&socket).expect("bind");
		let task = tokio::spawn(async move {
			let (mut stream, _) = listener.accept().await.expect("accept");
			let mut command = [0; 14];
			stream
				.read_exact(&mut command)
				.await
				.expect("empty request");
			let reply = format!("stream: {} FOUND\0", "x".repeat(length - 15));
			stream.write_all(reply.as_bytes()).await.expect("reply");
		});
		let metrics = Arc::new(Metrics::new());
		let hook = ClamdHook::new(socket).with_metrics(metrics.clone());
		let verdict = scan(&hook, b"").await;
		if length == MAX_REPLY_BYTES {
			assert_eq!(verdict, HookVerdict::Quarantine);
			assert_counters(&metrics, 0, 0);
		} else {
			assert_eq!(verdict, HookVerdict::Accept);
			assert_counters(&metrics, 1, 0);
		}
		task.await.expect("fake");
	}
}

#[tokio::test]
async fn disconnected_peer_and_blocked_write_fail_open() {
	for disconnect in [true, false] {
		let dir = tempfile::tempdir().expect("tempdir");
		let socket = dir.path().join("clamd.sock");
		let listener = UnixListener::bind(&socket).expect("bind");
		let (stop, stopped) = oneshot::channel();
		let task = tokio::spawn(async move {
			let (mut stream, _) = listener.accept().await.expect("accept");
			if disconnect {
				stream
					.into_std()
					.expect("std socket")
					.shutdown(std::net::Shutdown::Both)
					.expect("shutdown");
				return 0;
			}
			stopped.await.expect("scan completed");
			let mut bytes = Vec::new();
			stream
				.read_to_end(&mut bytes)
				.await
				.expect("drain closed socket");
			bytes.len()
		});
		let metrics = Arc::new(Metrics::new());
		let hook = ClamdHook::new(socket)
			.with_timeout(Duration::from_millis(200))
			.with_metrics(metrics.clone());
		let raw = vec![b'x'; 25 * 1024 * 1024];
		assert_eq!(scan(&hook, &raw).await, HookVerdict::Accept);
		assert_counters(&metrics, 1, 0);
		let _ = stop.send(());
		let written = task.await.expect("peer");
		assert!(
			written < raw.len(),
			"peer unexpectedly received the whole message"
		);
	}
}

#[tokio::test(flavor = "multi_thread")]
async fn stream_detection_logs_signature_and_size_without_message() {
	let raw = uuid::Uuid::now_v7().simple().to_string();
	let warnings = Warnings::default();
	let events = warnings.0.clone();
	let subscriber = tracing_subscriber::registry().with(warnings);
	// See detection_logs_signature_and_size_without_message above: set the
	// dispatcher for the whole test body via `block_in_place` +
	// `Handle::block_on` so the warn always lands on the capture layer.
	tokio::task::block_in_place(|| {
		tracing::subscriber::with_default(subscriber, || {
			tokio::runtime::Handle::current().block_on(async {
				let (client, mut server) = tokio::io::duplex(1024);
				let peer = tokio::spawn(async move {
					let mut request = [0; 50];
					server.read_exact(&mut request).await.expect("request");
					server
						.write_all(b"stream: Eicar-Test-Signature FOUND\0")
						.await
						.expect("reply");
				});
				let hook = ClamdHook::new(PathBuf::from("unused.sock"));
				assert_eq!(
					hook.scan_with(raw.as_bytes(), async { Ok(client) }).await,
					HookVerdict::Quarantine
				);
				peer.await.expect("fake");
			});
		});
	});
	let captured = events.lock().expect("warnings");
	assert_eq!(captured.len(), 1);
	assert!(captured[0].contains("signature=\"Eicar-Test-Signature\""));
	assert!(captured[0].contains(&format!("message_bytes={}", raw.len())));
	assert!(
		!captured[0].contains(&raw),
		"message content appeared in log"
	);
}
