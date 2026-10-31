//! F02: compressed hostile streams through a one-slot production listener.

use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::time::timeout;

use super::compress_support::*;
use super::harness::*;

async fn negotiate(stream: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin)) {
	send(stream, b"C COMPRESS DEFLATE\r\n").await;
	expect(stream, "C OK begin compression now\r\n").await;
}

#[test]
fn malformed_stream_cannot_execute_buffered_plaintext_after_compress() {
	watched(
		"compress::malformed_stream_cannot_execute_buffered_plaintext_after_compress",
		async {
			// Same malformed raw-DEFLATE bytes, split after the OK versus buffered
			// with COMPRESS. Neither placement may execute them as plaintext IMAP.
			for coalesced in [false, true] {
				let (mut client, data, _guard) = memory_authenticated().await;
				if coalesced {
					send(&mut client, b"C COMPRESS DEFLATE\r\nE CREATE forged\r\n").await;
					expect(&mut client, "C OK begin compression now\r\n").await;
				} else {
					negotiate(&mut client).await;
					send(&mut client, b"E CREATE forged\r\n").await;
				}
				let mut response = Vec::new();
				// Bounded output and EOF are required; a client-side timeout is a failure.
				let read = timeout(
					IO_DEADLINE,
					(&mut client).take(4097).read_to_end(&mut response),
				)
				.await
				.expect("malformed stream close deadline");
				// Error paths may close TLS without close_notify, as in the
				// existing hostile harness. An actual timeout is never accepted.
				if let Err(error) = read {
					assert!(is_close(&error), "unexpected close error: {error}");
				}
				assert!(
					response.len() <= 4096,
					"unbounded malformed-stream response"
				);
				assert!(
					!epistle::imap::mailbox::exists(data.path(), "tester", "forged"),
					"malformed compressed bytes executed as plaintext (coalesced={coalesced})"
				);
			}
		},
	);
}

#[test]
fn high_ratio_command_cannot_bypass_line_limit() {
	watched(
		"compress::high_ratio_command_cannot_bypass_line_limit",
		async {
			let server = Harness::start(|s| s.with_max_connections(1)).await;
			let mut client = server.connect().await;
			negotiate(&mut client).await;
			let mut command = b"A NOOP ".to_vec();
			command.resize(128 * 1024, b'x');
			command.extend_from_slice(b"\r\nE CREATE forged\r\n");
			let bomb = deflate(&command);
			assert!(bomb.len() < 1024, "fixture must have high expansion");
			send(&mut client, &bomb).await;
			Replies::new().expect(&mut client, TOO_LONG).await;
			closed(&mut client).await;
			empty_inbox(&server);
			server.healthy().await;
		},
	);
}

#[test]
fn high_ratio_literal_cannot_bypass_append_limit() {
	watched(
		"compress::high_ratio_literal_cannot_bypass_append_limit",
		async {
			let server =
				Harness::start(|s| s.with_max_connections(1).with_append_limit(1024)).await;
			let mut client = server.authenticated().await;
			negotiate(&mut client).await;
			let mut command = b"A APPEND INBOX {131072+}\r\n".to_vec();
			command.extend(vec![b'x'; 128 * 1024]);
			command.extend_from_slice(b"\r\nE CREATE forged\r\n");
			let bomb = deflate(&command);
			assert!(bomb.len() < 1024);
			send(&mut client, &bomb).await;
			Replies::new()
				.expect(&mut client, "* BYE literal too large\r\n")
				.await;
			closed(&mut client).await;
			empty_inbox(&server);
			assert!(!epistle::imap::mailbox::exists(
				server.data.path(),
				"tester",
				"forged"
			));
			server.healthy().await;
		},
	);
}

#[test]
fn malformed_deflate_closes_without_executing_tail() {
	watched(
		"compress::malformed_deflate_closes_without_executing_tail",
		async {
			let server = Harness::start(|s| s.with_max_connections(1)).await;
			let mut client = server.authenticated().await;
			negotiate(&mut client).await;
			// BFINAL=1, BTYPE=3 is reserved and invalid, not an incomplete block.
			send(&mut client, b"\x07E CREATE forged\r\n").await;
			closed(&mut client).await;
			empty_inbox(&server);
			assert!(!epistle::imap::mailbox::exists(
				server.data.path(),
				"tester",
				"forged"
			));
			server.healthy().await;
		},
	);
}

#[test]
fn truncated_huffman_table_at_eof_releases_slot() {
	watched(
		"compress::truncated_huffman_table_at_eof_releases_slot",
		async {
			let server = Harness::start(|s| s.with_max_connections(1)).await;
			let mut client = server.connect().await;
			negotiate(&mut client).await;
			// Dynamic Huffman block, cut off before the code-length alphabet.
			send(&mut client, b"\x05\x00").await;
			client.shutdown().await.expect("half-close truncated input");
			closed(&mut client).await;
			empty_inbox(&server);
			server.healthy().await;
		},
	);
}
