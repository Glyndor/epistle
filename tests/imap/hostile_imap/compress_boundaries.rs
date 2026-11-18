//! Compression boundaries must never turn untrusted trailing bytes into commands.

use flate2::{Compress, Compression, FlushCompress};
use tokio::io::AsyncWriteExt;

use super::compress_support::{Replies, memory_authenticated, watched};
use super::harness::*;

fn encode(codec: &mut Compress, input: &[u8], flush: FlushCompress) -> Vec<u8> {
	let before_in = codec.total_in();
	let before_out = codec.total_out();
	let mut bytes = vec![0; input.len() + 4096];
	codec.compress(input, &mut bytes, flush).expect("fixture");
	assert_eq!(codec.total_in() - before_in, input.len() as u64);
	bytes.truncate((codec.total_out() - before_out) as usize);
	bytes
}

#[test]
fn fragmented_commands_keep_one_compression_dictionary() {
	watched(
		"compress_boundaries::fragmented_commands_keep_one_compression_dictionary",
		async {
			let (mut client, data, _guard) = memory_authenticated().await;
			send(&mut client, b"C COMPRESS DEFLATE\r\n").await;
			expect(&mut client, "C OK begin compression now\r\n").await;
			let mut encoder = Compress::new(Compression::best(), false);
			let mut replies = Replies::new();
			// Every byte is a separate TLS write. Reusing the encoder across
			// commands makes later blocks refer back to the earlier dictionary.
			for (command, reply) in [
				("A CREATE boundary\r\n", "A OK CREATE completed\r\n"),
				("B DELETE boundary\r\n", "B OK DELETE completed\r\n"),
				("N NOOP\r\n", "N OK NOOP completed\r\n"),
			] {
				let encoded = encode(&mut encoder, command.as_bytes(), FlushCompress::Sync);
				for byte in encoded {
					send(&mut client, &[byte]).await;
					tokio::task::yield_now().await;
				}
				replies.expect(&mut client, reply).await;
			}
			assert!(!epistle::imap::mailbox::exists(
				data.path(),
				"tester",
				"boundary"
			));
		},
	);
}

#[test]
fn a_finished_deflate_stream_cannot_restart_as_plaintext_or_a_second_stream() {
	watched(
		"compress_boundaries::a_finished_deflate_stream_cannot_restart_as_plaintext_or_a_second_stream",
		async {
			for compressed_tail in [false, true] {
				let (mut client, data, _guard) = memory_authenticated().await;
				send(&mut client, b"C COMPRESS DEFLATE\r\n").await;
				expect(&mut client, "C OK begin compression now\r\n").await;
				let mut encoder = Compress::new(Compression::best(), false);
				let mut bytes = encode(&mut encoder, b"N NOOP\r\n", FlushCompress::Sync);
				bytes.extend(encode(&mut encoder, b"", FlushCompress::Finish));
				let tail = b"E CREATE forged\r\n";
				if compressed_tail {
					let mut second = Compress::new(Compression::best(), false);
					bytes.extend(encode(&mut second, tail, FlushCompress::Finish));
				} else {
					bytes.extend_from_slice(tail);
				}
				send(&mut client, &bytes).await;
				Replies::new()
					.expect(&mut client, "N OK NOOP completed\r\n")
					.await;
				closed(&mut client).await;
				assert!(!epistle::imap::mailbox::exists(
					data.path(),
					"tester",
					"forged"
				));
			}
		},
	);
}

#[test]
fn eof_in_a_compressed_append_never_commits_a_partial_message() {
	watched(
		"compress_boundaries::eof_in_a_compressed_append_never_commits_a_partial_message",
		async {
			let (mut client, data, _guard) = memory_authenticated().await;
			send(&mut client, b"C COMPRESS DEFLATE\r\n").await;
			expect(&mut client, "C OK begin compression now\r\n").await;
			let mut encoder = Compress::new(Compression::best(), false);
			let bytes = encode(
				&mut encoder,
				b"A APPEND INBOX {100+}\r\nSubject: incomplete\r\n\r\nx",
				FlushCompress::Sync,
			);
			send(&mut client, &bytes).await;
			client.shutdown().await.expect("half-close literal");
			closed(&mut client).await;
			assert!(
				epistle::imap::mailbox::Snapshot::open(
					data.path(),
					"tester",
					"INBOX",
					&epistle::storage::MessageCrypto::disabled(),
				)
				.expect("snapshot")
				.is_empty()
			);
		},
	);
}
