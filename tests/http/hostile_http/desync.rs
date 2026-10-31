//! Request desynchronization on one persistent connection. An ambiguous or
//! obfuscated framing header is followed, in the same write, by a request that
//! stores a second upload. The server must either
//! reject the ambiguous head or frame it one way, and in no case may the bytes
//! behind it run as a second request that the sender did not send as one.

use super::harness::{ADMIN, ALICE, Harness, Wire};

fn second_upload() -> String {
	format!(
		"POST /jmap/upload/alice HTTP/1.1\r\nHost: example.test\r\nAuthorization: Bearer {ALICE}\r\nContent-Type: text/plain\r\nContent-Length: 8\r\nConnection: close\r\n\r\nSMUGGLED"
	)
}

fn second_upload_stored(h: &Harness) -> bool {
	let dir = h.root().join("blobs/accounts/alice");
	let mut stored = false;
	let mut pending = vec![dir];
	while let Some(next) = pending.pop() {
		let Ok(entries) = std::fs::read_dir(next) else {
			continue;
		};
		for entry in entries.flatten() {
			let path = entry.path();
			if path.is_dir() {
				pending.push(path);
			} else if std::fs::read(&path).is_ok_and(|bytes| bytes == b"SMUGGLED") {
				stored = true;
			}
		}
	}
	stored
}

fn responses(reply: &[u8]) -> usize {
	reply.windows(9).filter(|w| *w == b"HTTP/1.1 ").count()
}

fn upload(framing: &str, body: &str) -> String {
	format!(
		"POST /jmap/upload/alice HTTP/1.1\r\nHost: example.test\r\nAuthorization: Bearer {ALICE}\r\nContent-Type: text/plain\r\n{framing}\r\n{body}"
	)
}

/// The second upload hides behind a zero-length chunk, so a parser that frames the
/// body by `Content-Length: 5` and one that frames it as chunked disagree
/// about where the first request ends.
fn hidden_behind_terminator(framing: &str) -> String {
	upload(framing, &format!("0\r\n\r\n{}", second_upload()))
}

#[tokio::test]
async fn a_valid_pipelined_upload_is_stored_so_the_oracle_can_see_execution() {
	let h = Harness::new();
	let wire = Wire::start(h.api.clone()).await;
	let first = format!(
		"GET /api/v1/accounts HTTP/1.1\r\nHost: example.test\r\nAuthorization: Bearer {ADMIN}\r\n\r\n"
	);
	let reply = wire
		.exchange(format!("{first}{}", second_upload()).as_bytes(), false)
		.await;
	assert_eq!(responses(&reply), 2, "{}", String::from_utf8_lossy(&reply));
	assert!(second_upload_stored(&h), "the second upload must have run");
}

#[tokio::test]
async fn ambiguous_framing_never_runs_the_bytes_behind_it() {
	for framing in [
		"Content-Length: 5\r\nTransfer-Encoding: chunked\r\n",
		"Transfer-Encoding: chunked\r\nContent-Length: 5\r\n",
		"Transfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n",
		"Transfer-Encoding : chunked\r\nContent-Length: 5\r\n",
		"Transfer-Encoding: xchunked\r\nContent-Length: 5\r\n",
		"Transfer-Encoding:\tchunked\r\nContent-Length: 5\r\n",
		"Transfer-Encoding:\r\n chunked\r\nContent-Length: 5\r\n",
		"Content-Length: 5\r\nContent-Length: 4\r\n",
		"Content-Length: 5, 4\r\n",
		"Content-Length: +5\r\n",
	] {
		let h = Harness::new();
		let wire = Wire::start(h.api.clone()).await;
		let reply = wire
			.exchange(hidden_behind_terminator(framing).as_bytes(), false)
			.await;
		let text = String::from_utf8_lossy(&reply);
		assert!(
			responses(&reply) <= 1,
			"{framing:?} produced several responses:\n{text}"
		);
		assert!(
			!second_upload_stored(&h),
			"{framing:?} stored the second upload:
{text}"
		);
		wire.healthy().await;
	}
}

#[tokio::test]
async fn an_early_rejection_does_not_leave_the_body_to_be_read_as_a_request() {
	let h = Harness::new();
	let wire = Wire::start(h.api.clone()).await;
	// No credential: the route refuses before it reads the body.
	let request = format!(
		"POST /jmap/upload/alice HTTP/1.1\r\nHost: example.test\r\nContent-Length: {}\r\n\r\n{}",
		second_upload().len(),
		second_upload()
	);
	let reply = wire.exchange(request.as_bytes(), true).await;
	assert!(
		responses(&reply) <= 1,
		"{}",
		String::from_utf8_lossy(&reply)
	);
	assert!(!second_upload_stored(&h));
}

#[tokio::test]
async fn chunk_extension_with_a_bare_line_feed_cannot_split_a_request() {
	let h = Harness::new();
	let wire = Wire::start(h.api.clone()).await;
	let request = upload(
		"Transfer-Encoding: chunked\r\n",
		&format!("2;x=\n{}\r\n0\r\n\r\n", second_upload()),
	);
	let reply = wire.exchange(request.as_bytes(), false).await;
	assert!(
		responses(&reply) <= 1,
		"{}",
		String::from_utf8_lossy(&reply)
	);
	assert!(!second_upload_stored(&h));
}
