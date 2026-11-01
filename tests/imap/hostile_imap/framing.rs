//! Literal sizes, line framing and hostile command octets on real sockets.

use super::harness::*;

async fn giant(synchronizing: bool, size: &str) {
	let server = Harness::start(|s| s).await;
	let mut client = server.authenticated().await;
	let plus = if synchronizing { "" } else { "+" };
	// Send the announcement only. A continuation or a wait for data is a failure.
	send(
		&mut client,
		format!("A1 APPEND INBOX {{{size}{plus}}}\r\n").as_bytes(),
	)
	.await;
	if synchronizing {
		expect(
			&mut client,
			"A1 NO [TOOBIG] message exceeds APPENDLIMIT\r\n",
		)
		.await;
		noop(&mut client).await;
		logout(&mut client).await;
	} else {
		expect(&mut client, "* BYE literal too large\r\n").await;
		closed(&mut client).await;
	}
	assert!(
		epistle::imap::mailbox::Snapshot::open(
			server.data.path(),
			"tester",
			"INBOX",
			&epistle::storage::MessageCrypto::disabled()
		)
		.expect("inbox snapshot")
		.is_empty()
	);
	server.healthy().await;
}

#[tokio::test]
async fn literal_u32_max_is_rejected_before_continuation() {
	giant(true, "4294967295").await;
}

#[tokio::test]
async fn literal_eleven_digits_is_rejected_before_continuation() {
	giant(true, "99999999999").await;
}

#[tokio::test]
async fn literal_plus_u32_max_closes_before_payload() {
	giant(false, "4294967295").await;
}

#[tokio::test]
async fn literal_plus_eleven_digits_closes_before_payload() {
	giant(false, "99999999999").await;
}

#[tokio::test]
async fn command_over_32_kib_gets_bye_and_closes() {
	let server = Harness::start(|s| s).await;
	let mut client = server.connect().await;
	let mut command = b"A1 NOOP ".to_vec();
	command.resize(32 * 1024 + 1, b'x');
	command.extend_from_slice(b"\r\n");
	send(&mut client, &command).await;
	expect(&mut client, TOO_LONG).await;
	closed(&mut client).await;
	server.healthy().await;
}

#[tokio::test]
async fn repeated_rejected_literal_plus_payloads_never_become_commands() {
	let server = Harness::start(|s| s).await;
	let mut client = server.authenticated().await;
	// The payload would create a mailbox if the discard path replayed it.
	let payload = b"E CREATE forged\r\n";
	let mut bomb = format!("A1 APPEND Missing {{{}+}}\r\n", payload.len()).into_bytes();
	bomb.extend_from_slice(payload);
	for _ in 0..128 {
		bomb.extend_from_slice(format!(" {{{}+}}\r\n", payload.len()).as_bytes());
		bomb.extend_from_slice(payload);
	}
	bomb.extend_from_slice(b"\r\nN NOOP\r\n");
	send(&mut client, &bomb).await;
	expect(&mut client, "A1 NO [TRYCREATE] no such mailbox\r\n").await;
	expect(&mut client, "N OK NOOP completed\r\n").await;
	assert!(!epistle::imap::mailbox::exists(
		server.data.path(),
		"tester",
		"forged"
	));
	assert!(select_inbox(&mut client).await.contains("* 0 EXISTS\r\n"));
	logout(&mut client).await;
	server.healthy().await;
}

#[tokio::test]
async fn oversized_literal_plus_in_rejected_tail_closes() {
	let server = Harness::start(|s| s).await;
	let mut client = server.connect().await;
	send(&mut client, b"A1 APPEND INBOX {1+}\r\nx {4294967295+}\r\n").await;
	expect(&mut client, "A1 NO not authenticated\r\n").await;
	expect(&mut client, "* BYE literal too large\r\n").await;
	closed(&mut client).await;
	server.healthy().await;
}

#[tokio::test]
async fn tag_control_bytes_are_bad_and_never_echoed() {
	let server = Harness::start(|s| s).await;
	for byte in [1, 9, 27, 31, 127] {
		let mut client = server.connect().await;
		let command = [b'A', byte, b' ', b'N', b'O', b'O', b'P', b'\r', b'\n'];
		send(&mut client, &command).await;
		expect(&mut client, "* BAD malformed command\r\n").await;
		noop(&mut client).await;
		logout(&mut client).await;
		server.healthy().await;
	}
}

#[tokio::test]
async fn crlf_inside_quoted_astring_rejects_both_fragments() {
	let server = Harness::start(|s| s).await;
	let mut client = server.authenticated().await;
	send(
		&mut client,
		b"A1 CREATE \"broken\r\nstill-quoted\"\r\nN NOOP\r\n",
	)
	.await;
	expect(&mut client, "A1 BAD invalid arguments\r\n").await;
	expect(&mut client, "* BAD malformed command\r\n").await;
	expect(&mut client, "N OK NOOP completed\r\n").await;
	assert!(!epistle::imap::mailbox::exists(
		server.data.path(),
		"tester",
		"broken"
	));
	logout(&mut client).await;
	server.healthy().await;
}

#[tokio::test]
async fn nul_and_bare_line_endings_close_with_protocol_error() {
	let server = Harness::start(|s| s).await;
	for command in [b"A1 NO\0OP\r\n".as_slice(), b"A1 NO\rOP\r\n", b"A1 NOOP\n"] {
		let mut client = server.connect().await;
		send(&mut client, command).await;
		expect(&mut client, PROTOCOL).await;
		closed(&mut client).await;
		server.healthy().await;
	}
}

#[tokio::test]
async fn every_invalid_high_octet_is_bad_without_losing_framing() {
	let server = Harness::start(|s| s).await;
	for byte in 0x80..=0xff {
		let mut client = server.connect().await;
		let command = [b'A', b'1', b' ', byte, b'\r', b'\n'];
		send(&mut client, &command).await;
		expect(&mut client, "* BAD non-ASCII command\r\n").await;
		noop(&mut client).await;
		logout(&mut client).await;
		server.healthy().await;
	}
}
