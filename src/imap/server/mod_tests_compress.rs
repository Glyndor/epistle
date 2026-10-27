//! COMPRESS=DEFLATE driven end to end against the real connection loop.
//!
//! The unit tests in `compress_tests.rs` exercise the wrapper in isolation.
//! These go in through the server: they prove the loop actually swaps the
//! stream, that the tagged OK arrives uncompressed as RFC 4978 §3 requires,
//! and that commands sent after it are understood. A wrapper that works and a
//! loop that never installs it look identical from the unit tests.

use super::tests::plaintext_server;
use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A client-side deflate context, kept for the whole connection like a real
/// client's.
struct ClientCodec {
	compress: Compress,
	decompress: Decompress,
}

impl ClientCodec {
	fn new() -> Self {
		ClientCodec {
			compress: Compress::new(Compression::default(), false),
			decompress: Decompress::new(false),
		}
	}

	fn deflate(&mut self, bytes: &[u8]) -> Vec<u8> {
		let before = self.compress.total_out();
		let mut out = vec![0u8; bytes.len() + 4096];
		self.compress
			.compress(bytes, &mut out, FlushCompress::Sync)
			.expect("deflate");
		let produced = usize::try_from(self.compress.total_out() - before).expect("fits");
		out.truncate(produced);
		out
	}

	fn inflate(&mut self, bytes: &[u8]) -> String {
		let before = self.decompress.total_out();
		let mut out = vec![0u8; 64 * 1024];
		self.decompress
			.decompress(bytes, &mut out, FlushDecompress::None)
			.expect("inflate");
		let produced = usize::try_from(self.decompress.total_out() - before).expect("fits");
		String::from_utf8_lossy(&out[..produced]).to_string()
	}
}

async fn read_raw(client: &mut tokio::io::DuplexStream) -> Vec<u8> {
	let mut chunk = vec![0u8; 64 * 1024];
	let read = client.read(&mut chunk).await.expect("read");
	chunk.truncate(read);
	chunk
}

#[tokio::test]
async fn capability_advertises_compress_deflate() {
	let (mut client, task) = plaintext_server();
	let _greeting = read_raw(&mut client).await;
	client.write_all(b"a1 CAPABILITY\r\n").await.expect("write");
	let response = String::from_utf8_lossy(&read_raw(&mut client).await).to_string();
	assert!(response.contains("COMPRESS=DEFLATE"), "{response}");
	drop(client);
	let _ = task.await;
}

#[tokio::test]
async fn compress_deflate_switches_the_stream_after_an_uncompressed_ok() {
	let (mut client, task) = plaintext_server();
	let _greeting = read_raw(&mut client).await;

	client
		.write_all(b"a1 COMPRESS DEFLATE\r\n")
		.await
		.expect("write");
	// RFC 4978 §3: this one is still in the clear. Reading it as plaintext is
	// the assertion — if the server compressed it, this would be binary.
	let ok = String::from_utf8_lossy(&read_raw(&mut client).await).to_string();
	assert!(ok.contains("a1 OK"), "{ok}");

	// Everything from here is deflated, both ways.
	let mut codec = ClientCodec::new();
	let request = codec.deflate(b"a2 NOOP\r\n");
	client.write_all(&request).await.expect("write");
	let raw = read_raw(&mut client).await;
	let response = codec.inflate(&raw);
	assert!(response.contains("a2 OK NOOP"), "{response}");
	drop(client);
	let _ = task.await;
}

#[tokio::test]
async fn a_second_compress_is_refused_without_restarting_the_context() {
	let (mut client, task) = plaintext_server();
	let _greeting = read_raw(&mut client).await;
	client
		.write_all(b"a1 COMPRESS DEFLATE\r\n")
		.await
		.expect("write");
	let _ok = read_raw(&mut client).await;

	let mut codec = ClientCodec::new();
	client
		.write_all(&codec.deflate(b"a2 COMPRESS DEFLATE\r\n"))
		.await
		.expect("write");
	let response = codec.inflate(&read_raw(&mut client).await);
	// NO, not BAD: the command is well formed, the state is wrong. And the
	// answer arrives compressed, which is what proves the context was not
	// torn down and restarted underneath the client.
	assert!(response.contains("a2 NO"), "{response}");
	assert!(response.contains("COMPRESSIONACTIVE"), "{response}");
	drop(client);
	let _ = task.await;
}

#[tokio::test]
async fn an_unknown_compress_algorithm_is_bad_and_leaves_the_stream_alone() {
	let (mut client, task) = plaintext_server();
	let _greeting = read_raw(&mut client).await;
	client
		.write_all(b"a1 COMPRESS LZW\r\n")
		.await
		.expect("write");
	let response = String::from_utf8_lossy(&read_raw(&mut client).await).to_string();
	assert!(response.contains("a1 BAD"), "{response}");

	// Still plaintext: a refused algorithm must not have switched anything.
	client.write_all(b"a2 NOOP\r\n").await.expect("write");
	let after = String::from_utf8_lossy(&read_raw(&mut client).await).to_string();
	assert!(after.contains("a2 OK NOOP"), "{after}");
	drop(client);
	let _ = task.await;
}
