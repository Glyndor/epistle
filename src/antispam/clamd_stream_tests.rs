//! Protocol and deadline checks using in-memory streams without socket syscalls.

use super::*;

use tokio::io::{DuplexStream, duplex};

async fn exchange(
	raw: &[u8],
	reply: Vec<u8>,
	action: HookVerdict,
) -> (HookVerdict, Arc<Metrics>, Vec<u8>) {
	let (client, mut server) = duplex(1024);
	let wire_length = 10 + raw.len() + raw.len().div_ceil(65536) * 4 + 4;
	let peer = tokio::spawn(async move {
		let mut wire = vec![0; wire_length];
		server.read_exact(&mut wire).await.expect("request");
		for byte in reply {
			server.write_all(&[byte]).await.expect("reply fragment");
			tokio::task::yield_now().await;
		}
		wire
	});
	let metrics = Arc::new(Metrics::new());
	let hook = ClamdHook::new(PathBuf::from("unused.sock"))
		.with_on_found(action)
		.with_metrics(metrics.clone());
	let verdict = tokio::time::timeout(
		Duration::from_secs(2),
		hook.scan_with(raw, async { Ok(client) }),
	)
	.await
	.expect("test deadline");
	(verdict, metrics, peer.await.expect("fake"))
}

#[tokio::test]
async fn fragmented_replies_and_chunk_framing() {
	let raw: Vec<u8> = (0..200 * 1024).map(|i| (i % 251) as u8).collect();
	let (verdict, metrics, wire) =
		exchange(&raw, b"stream: OK\0".to_vec(), HookVerdict::Quarantine).await;
	assert_eq!(verdict, HookVerdict::Accept);
	assert_eq!(metrics.snapshot().get("scanner_clamd_failed"), Some(&0));
	assert!(wire.starts_with(b"zINSTREAM\0"));
	let mut rest = &wire[10..];
	let mut payload = Vec::new();
	for expected in [65536, 65536, 65536, 8192] {
		let length = u32::from_be_bytes(rest[..4].try_into().expect("header")) as usize;
		assert_eq!(length, expected, "big-endian chunk length");
		payload.extend_from_slice(&rest[4..4 + length]);
		rest = &rest[4 + length..];
	}
	assert_eq!(rest, &[0; 4]);
	assert!(payload == raw, "payload changed");
}

#[tokio::test]
async fn stream_verdicts_and_failures() {
	for (reply, action, expected, failures) in [
		(
			b"stream: OK\0".as_slice(),
			HookVerdict::Reject,
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
		let (verdict, metrics, _) = exchange(b"msg", reply.to_vec(), action).await;
		assert_eq!(verdict, expected);
		assert_eq!(
			metrics.snapshot().get("scanner_clamd_failed"),
			Some(&failures)
		);
		assert_eq!(metrics.snapshot().get("scanner_clamd_skipped"), Some(&0));
	}
}

#[tokio::test]
async fn stream_size_limit_skips_connection_and_includes_boundary() {
	for size in [4, 5] {
		let metrics = Arc::new(Metrics::new());
		let hook = ClamdHook::new(PathBuf::from("unused.sock"))
			.with_max_bytes(4)
			.with_metrics(metrics.clone());
		let connected = AtomicU64::new(0);
		let (client, mut server) = duplex(1024);
		let peer = tokio::spawn(async move {
			let mut command = [0; 10];
			let received = server.read(&mut command).await.expect("command");
			let mut bytes = command[..received].to_vec();
			if received > 0 {
				server
					.write_all(b"stream: Eicar-Test-Signature FOUND\0")
					.await
					.expect("reply");
				server.read_to_end(&mut bytes).await.expect("request");
			}
			bytes
		});
		let connect = async {
			connected.fetch_add(1, Ordering::Relaxed);
			Ok(client)
		};
		let verdict = hook.scan_with(&vec![b'x'; size], connect).await;
		let bytes = peer.await.expect("peer");
		if size == 4 {
			assert_eq!(verdict, HookVerdict::Quarantine);
			assert_eq!(connected.load(Ordering::Relaxed), 1);
			assert_eq!(metrics.snapshot().get("scanner_clamd_skipped"), Some(&0));
			assert!(!bytes.is_empty());
		} else {
			assert_eq!(verdict, HookVerdict::Accept);
			assert_eq!(
				connected.load(Ordering::Relaxed),
				0,
				"oversize opened a connection"
			);
			assert_eq!(metrics.snapshot().get("scanner_clamd_skipped"), Some(&1));
			assert!(bytes.is_empty(), "oversize wrote to stream");
		}
		assert_eq!(metrics.snapshot().get("scanner_clamd_failed"), Some(&0));
	}
}

#[tokio::test(start_paused = true)]
async fn deadline_bounds_connect_write_and_read() {
	for phase in ["connect", "write", "read"] {
		let metrics = Arc::new(Metrics::new());
		let hook = ClamdHook::new(PathBuf::from("unused.sock"))
			.with_timeout(Duration::from_millis(200))
			.with_metrics(metrics.clone());
		let (client, mut server) = duplex(if phase == "write" { 1 } else { 1024 });
		let connect = async {
			if phase == "connect" {
				std::future::pending::<()>().await;
			}
			Ok(client)
		};
		let start = tokio::time::Instant::now();
		let verdict = tokio::time::timeout(Duration::from_secs(1), hook.scan_with(b"msg", connect))
			.await
			.expect("whole exchange deadline");
		assert_eq!(verdict, HookVerdict::Accept);
		assert_eq!(
			start.elapsed(),
			Duration::from_millis(200),
			"{phase} timeout"
		);
		assert_eq!(metrics.snapshot().get("scanner_clamd_failed"), Some(&1));
		let mut wire = Vec::new();
		server.read_to_end(&mut wire).await.expect("drain");
		assert_eq!(
			wire.len(),
			match phase {
				"connect" => 0,
				"write" => 1,
				_ => 21,
			}
		);
	}
}

#[tokio::test]
async fn connection_and_write_errors_fail_open() {
	for connect_error in [true, false] {
		let metrics = Arc::new(Metrics::new());
		let hook = ClamdHook::new(PathBuf::from("unused.sock")).with_metrics(metrics.clone());
		let (client, server) = duplex(1);
		drop(server);
		let connect = async {
			if connect_error {
				Err(io::Error::from(io::ErrorKind::ConnectionRefused))
			} else {
				Ok::<DuplexStream, io::Error>(client)
			}
		};
		assert_eq!(hook.scan_with(b"msg", connect).await, HookVerdict::Accept);
		assert_eq!(metrics.snapshot().get("scanner_clamd_failed"), Some(&1));
	}
}

#[tokio::test]
async fn stream_reply_limit_includes_boundary() {
	for length in [MAX_REPLY_BYTES, MAX_REPLY_BYTES + 1] {
		let reply = format!("stream: {} FOUND\0", "x".repeat(length - 15));
		let (verdict, metrics, _) =
			exchange(b"", reply.into_bytes(), HookVerdict::Quarantine).await;
		if length == MAX_REPLY_BYTES {
			assert_eq!(verdict, HookVerdict::Quarantine);
			assert_eq!(metrics.snapshot().get("scanner_clamd_failed"), Some(&0));
		} else {
			assert_eq!(verdict, HookVerdict::Accept);
			assert_eq!(metrics.snapshot().get("scanner_clamd_failed"), Some(&1));
		}
	}
}
