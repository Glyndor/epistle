//! The wrapper is driven through `tokio::io::duplex`, which is a real async
//! stream with a bounded buffer, so partial writes and pending reads happen
//! the way they do on a socket rather than being assumed away.

use super::*;
use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Inflate `bytes` as a raw deflate stream, the way a client would.
fn inflate(bytes: &[u8]) -> Vec<u8> {
	let mut out = vec![0u8; 64 * 1024];
	let mut decompress = Decompress::new(false);
	decompress
		.decompress(bytes, &mut out, FlushDecompress::None)
		.expect("inflate");
	let produced = usize::try_from(decompress.total_out()).expect("fits");
	out.truncate(produced);
	out
}

/// Deflate `bytes` as a raw deflate stream, the way a client would.
fn deflate(bytes: &[u8]) -> Vec<u8> {
	let mut out = vec![0u8; bytes.len() + 1024];
	let mut compress = Compress::new(Compression::default(), false);
	compress
		.compress(bytes, &mut out, FlushCompress::Sync)
		.expect("deflate");
	let produced = usize::try_from(compress.total_out()).expect("fits");
	out.truncate(produced);
	out
}

#[tokio::test]
async fn what_the_server_writes_inflates_back_to_what_it_wrote() {
	let (server_side, mut client_side) = tokio::io::duplex(64 * 1024);
	let mut deflated = Deflate::new(server_side);

	deflated.write_all(b"* OK ready\r\n").await.expect("write");
	deflated.flush().await.expect("flush");

	let mut raw = vec![0u8; 4096];
	let read = client_side.read(&mut raw).await.expect("read");
	assert!(read > 0, "nothing reached the wire");
	assert_eq!(inflate(&raw[..read]), b"* OK ready\r\n");
}

#[tokio::test]
async fn what_a_client_deflates_arrives_as_plaintext() {
	let (server_side, mut client_side) = tokio::io::duplex(64 * 1024);
	let mut deflated = Deflate::new(server_side);

	client_side
		.write_all(&deflate(b"a1 NOOP\r\n"))
		.await
		.expect("client write");
	client_side.flush().await.expect("client flush");

	let mut plain = vec![0u8; 64];
	let read = deflated.read(&mut plain).await.expect("read");
	assert_eq!(&plain[..read], b"a1 NOOP\r\n");
}

#[tokio::test]
async fn the_context_persists_so_a_repeated_line_costs_less_the_second_time() {
	// This is the whole point of RFC 4978: one deflate context for the
	// connection, not one per message. If the wrapper reset the compressor
	// between writes the two sizes would match, and the feature would be
	// doing nothing while appearing to work.
	let (server_side, mut client_side) = tokio::io::duplex(64 * 1024);
	let mut deflated = Deflate::new(server_side);
	let line = b"* 1 FETCH (FLAGS (\\Seen) UID 1 RFC822.SIZE 4242)\r\n";

	deflated.write_all(line).await.expect("write");
	deflated.flush().await.expect("flush");
	let mut raw = vec![0u8; 4096];
	let first = client_side.read(&mut raw).await.expect("read");

	deflated.write_all(line).await.expect("write");
	deflated.flush().await.expect("flush");
	let second = client_side.read(&mut raw).await.expect("read");

	assert!(
		second < first,
		"the second copy of the same line cost {second} bytes against {first}; \
		 the deflate context is not being kept",
	);
}

#[tokio::test]
async fn a_write_larger_than_one_pass_survives_intact() {
	// 8 KiB is the working buffer, so this crosses it and exercises the
	// partial-consume path in poll_write that `write_all` loops over.
	let (server_side, mut client_side) = tokio::io::duplex(1024 * 1024);
	let mut deflated = Deflate::new(server_side);
	let body: Vec<u8> = (0..40_000u32)
		.map(|i| b"abcdefgh"[(i % 8) as usize])
		.collect();

	deflated.write_all(&body).await.expect("write");
	deflated.flush().await.expect("flush");

	let mut raw = Vec::new();
	let mut chunk = vec![0u8; 64 * 1024];
	// One read is enough for a duplex this size, but loop in case it splits.
	loop {
		let read = client_side.read(&mut chunk).await.expect("read");
		raw.extend_from_slice(&chunk[..read]);
		if inflate(&raw).len() >= body.len() || read == 0 {
			break;
		}
	}
	assert_eq!(inflate(&raw), body);
}

#[tokio::test]
async fn a_read_split_across_packets_still_reassembles() {
	// A deflate block arriving in two reads must not lose the half that was
	// held back. A sync-flushed block decodes its own prefix, so the first
	// read may legitimately return part of the line — what must not happen is
	// the remainder going missing when the wrapper refills its input.
	let (server_side, mut client_side) = tokio::io::duplex(64 * 1024);
	let mut deflated = Deflate::new(server_side);
	let compressed = deflate(b"a1 SELECT INBOX\r\n");
	let (head, tail) = compressed.split_at(compressed.len() / 2);

	client_side.write_all(head).await.expect("head");
	client_side.flush().await.expect("flush head");

	let reader = tokio::spawn(async move {
		let mut plain = Vec::new();
		let mut chunk = vec![0u8; 64];
		while plain.len() < b"a1 SELECT INBOX\r\n".len() {
			let read = deflated.read(&mut chunk).await.expect("read");
			if read == 0 {
				break;
			}
			plain.extend_from_slice(&chunk[..read]);
		}
		plain
	});
	// Let the reader consume the first half and block on the rest.
	tokio::task::yield_now().await;
	client_side.write_all(tail).await.expect("tail");
	client_side.flush().await.expect("flush tail");

	assert_eq!(reader.await.expect("join"), b"a1 SELECT INBOX\r\n");
}

#[tokio::test]
async fn end_of_the_inner_stream_reads_as_end_of_file() {
	let (server_side, client_side) = tokio::io::duplex(64 * 1024);
	let mut deflated = Deflate::new(server_side);
	drop(client_side);
	let mut plain = vec![0u8; 16];
	assert_eq!(deflated.read(&mut plain).await.expect("read"), 0);
}
