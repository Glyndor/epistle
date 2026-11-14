//! Malformed chunk metadata must not dispatch a request hidden in the body.

use super::harness::{ALICE, Harness, Wire};

const CANARY: &str = "framing-matrix-canary";

fn tail() -> String {
	format!(
		"POST /jmap/upload/alice HTTP/1.1\r\nHost: example.test\r\nAuthorization: Bearer {ALICE}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{CANARY}",
		CANARY.len()
	)
}

fn canary_count(h: &Harness) -> usize {
	let mut pending = vec![h.root().join("blobs/accounts/alice")];
	let mut count = 0;
	while let Some(path) = pending.pop() {
		let Ok(entries) = std::fs::read_dir(path) else {
			continue;
		};
		for entry in entries {
			let path = entry.expect("blob entry").path();
			if path.is_dir() {
				pending.push(path);
			} else if std::fs::read(path).expect("blob content") == CANARY.as_bytes() {
				count += 1;
			}
		}
	}
	count
}

async fn attack(framing: &str, body: &str) {
	let h = Harness::new();
	let wire = Wire::start(h.api.clone()).await;
	let request = format!(
		"POST /jmap/upload/alice HTTP/1.1\r\nHost: example.test\r\nAuthorization: Bearer {ALICE}\r\nContent-Type: text/plain\r\n{framing}\r\n{body}{}",
		tail()
	);
	// Half-close makes truncated sizes observable without waiting for idle expiry.
	let reply = wire.exchange(request.as_bytes(), true).await;
	assert!(
		reply.windows(9).filter(|b| *b == b"HTTP/1.1 ").count() <= 1,
		"{framing:?} {body:?}: {}",
		String::from_utf8_lossy(&reply)
	);
	assert_eq!(
		canary_count(&h),
		0,
		"hidden upload ran: {framing:?} {body:?}"
	);
	wire.healthy().await;
}

#[tokio::test]
async fn invalid_chunk_sizes_cannot_dispatch_a_hidden_upload() {
	for body in [
		"+0\r\n\r\n",
		"0x0\r\n\r\n",
		"-1\r\n\r\n",
		"g\r\n\r\n",
		"10000000000000000\r\n\r\n",
		"1\r\nxX\r\n0\r\n\r\n", // missing CRLF after chunk data
		"1\r\nx\r\nZ\r\n\r\n",
	] {
		attack("Transfer-Encoding: chunked\r\n", body).await;
	}
}

#[tokio::test]
async fn invalid_length_spellings_cannot_dispatch_a_hidden_upload() {
	for length in [
		"-1",
		"0x5",
		"5 5",
		"18446744073709551616",
		"5, 0",
		"5\r\nContent-Length: 0",
	] {
		attack(&format!("Content-Length: {length}\r\n"), "0\r\n\r\n").await;
	}
}

#[tokio::test]
async fn a_valid_chunk_extension_and_trailer_preserve_the_pipeline() {
	let h = Harness::new();
	let wire = Wire::start(h.api.clone()).await;
	let request = format!(
		"POST /jmap/upload/alice HTTP/1.1\r\nHost: example.test\r\nAuthorization: Bearer {ALICE}\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\nTrailer: X-Checksum\r\n\r\n1;name=value\r\nx\r\n0\r\nX-Checksum: ok\r\n\r\n{}",
		tail()
	);
	let reply = wire.exchange(request.as_bytes(), false).await;
	assert_eq!(
		reply.windows(9).filter(|b| *b == b"HTTP/1.1 ").count(),
		2,
		"{}",
		String::from_utf8_lossy(&reply)
	);
	assert_eq!(
		canary_count(&h),
		1,
		"valid pipeline must execute the canary"
	);
	wire.healthy().await;
}
