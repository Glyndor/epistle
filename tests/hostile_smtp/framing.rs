//! Framing and envelope injection attacks, using literal hostile octets.

use super::harness::*;

async fn smuggling(separator: &[u8]) {
	let server = Harness::start(|s| s).await;
	let mut client = server.connect().await;
	helo(&mut client).await;
	data(&mut client).await;
	let mut payload = b"From: sender@remote.test\r\nSubject: outer\r\n\r\nouter".to_vec();
	payload.extend_from_slice(separator);
	payload.extend_from_slice(
		b"MAIL FROM:<forged@remote.test>\r\nRCPT TO:<tester@epistle.test>\r\n\
DATA\r\nSubject: smuggled\r\n\r\nforged\r\n.\r\n",
	);
	send(&mut client, &payload).await;
	expect(&mut client, BARE).await;
	closed(&mut client).await;
	assert!(
		server.sink.messages().is_empty(),
		"neither message may be delivered"
	);
	server.healthy().await;
}

#[tokio::test]
async fn smuggling_lf_dot_lf_is_rejected_with_554_and_no_delivery() {
	if !super::enabled() {
		return;
	}
	smuggling(b"\n.\n").await;
}

#[tokio::test]
async fn smuggling_cr_dot_cr_is_rejected_with_554_and_no_delivery() {
	if !super::enabled() {
		return;
	}
	smuggling(b"\r.\r").await;
}

#[tokio::test]
async fn smuggling_lf_dot_crlf_is_rejected_with_554_and_no_delivery() {
	if !super::enabled() {
		return;
	}
	smuggling(b"\n.\r\n").await;
}

#[tokio::test]
async fn command_over_512_octets_gets_500_without_executing_it() {
	if !super::enabled() {
		return;
	}
	let server = Harness::start(|s| s).await;
	let mut client = server.connect().await;
	// Pin both sides of the documented command cap, independently of constants.
	let accepted = format!("NOOP {}\r\n", "x".repeat(507));
	send(&mut client, accepted.as_bytes()).await;
	expect(&mut client, OK).await;
	let refused = format!("NOOP {}\r\n", "x".repeat(508));
	send(&mut client, refused.as_bytes()).await;
	expect(&mut client, "500 5.5.2 line too long\r\n").await;
	quit(&mut client).await;
	server.healthy().await;
}

#[tokio::test]
async fn data_line_over_998_octets_gets_500_and_connection_closes() {
	if !super::enabled() {
		return;
	}
	let server = Harness::start(|s| s).await;
	let mut client = server.connect().await;
	helo(&mut client).await;
	data(&mut client).await;
	let mut body = b"Subject: boundary\r\n\r\n".to_vec();
	body.extend(vec![b'x'; 998]);
	body.extend_from_slice(b"\r\n.\r\n");
	send(&mut client, &body).await;
	expect(&mut client, OK).await;
	data(&mut client).await;
	let mut body = vec![b'x'; 999];
	body.extend_from_slice(b"\r\n.\r\n");
	send(&mut client, &body).await;
	expect(&mut client, LONG).await;
	closed(&mut client).await;
	assert_eq!(
		server.sink.messages().len(),
		1,
		"only the boundary message delivered"
	);
	server.healthy().await;
}

async fn inject(prefix: &[u8], suffix: &[u8], recipient: bool) {
	let server = Harness::start(|s| s).await;
	for separator in [b"\r".as_slice(), b"\n".as_slice(), b"\r\n".as_slice()] {
		let mut client = server.connect().await;
		ehlo(&mut client).await;
		if recipient {
			send(&mut client, b"MAIL FROM:<sender@remote.test>\r\n").await;
			expect(&mut client, OK).await;
		}
		let mut payload = prefix.to_vec();
		payload.extend_from_slice(separator);
		payload.extend_from_slice(b"Bcc: victim@remote.test\r\n");
		payload.extend_from_slice(suffix);
		send(&mut client, &payload).await;
		if separator == b"\r\n" {
			// CRLF really ends a command. Incomplete paths/values and the
			// forged header must all be refused rather than enter the envelope.
			expect(&mut client, BAD_ARGS).await;
			expect(&mut client, SYNTAX).await;
			if !suffix.is_empty() {
				expect(&mut client, SYNTAX).await;
			}
			send(&mut client, b"DATA\r\n").await;
			expect(&mut client, "503 5.5.1 bad sequence of commands\r\n").await;
			quit(&mut client).await;
		} else {
			expect(&mut client, BARE).await;
			closed(&mut client).await;
		}
		assert!(server.sink.messages().is_empty());
		server.healthy().await;
	}
}

#[tokio::test]
async fn mail_from_header_crlf_injection_cannot_create_an_envelope() {
	if !super::enabled() {
		return;
	}
	inject(b"MAIL FROM:<sender@", b"remote.test>\r\n", false).await;
}

#[tokio::test]
async fn rcpt_to_header_crlf_injection_cannot_add_a_recipient() {
	if !super::enabled() {
		return;
	}
	inject(b"RCPT TO:<tester@", b"epistle.test>\r\n", true).await;
}

#[tokio::test]
async fn esmtp_parameter_crlf_injection_is_refused_without_delivery() {
	if !super::enabled() {
		return;
	}
	inject(b"MAIL FROM:<sender@remote.test> BODY=8BIT", b"", false).await;
}

#[tokio::test]
async fn nul_in_command_gets_554_and_connection_closes() {
	if !super::enabled() {
		return;
	}
	let server = Harness::start(|s| s).await;
	let mut client = server.connect().await;
	send(&mut client, b"NOOP\0injected\r\n").await;
	expect(
		&mut client,
		"554 5.5.2 NUL byte received, closing connection\r\n",
	)
	.await;
	closed(&mut client).await;
	server.healthy().await;
}

#[tokio::test]
async fn command_bytes_80_through_ff_get_500_without_execution() {
	if !super::enabled() {
		return;
	}
	let server = Harness::start(|s| s).await;
	// New connections avoid mistaking the error-streak cap for UTF-8 rejection.
	for byte in 0x80..=0xff {
		let mut client = server.connect().await;
		send(
			&mut client,
			&[b'N', b'O', b'O', b'P', b' ', byte, b'\r', b'\n'],
		)
		.await;
		expect(&mut client, SYNTAX).await;
		quit(&mut client).await;
	}
	server.healthy().await;
}

#[tokio::test]
async fn giant_unterminated_ehlo_gets_500_and_connection_closes() {
	if !super::enabled() {
		return;
	}
	let server = Harness::start(|s| s).await;
	let mut client = server.connect().await;
	// No CRLF: the decoder must cap its open line, not wait for a terminator.
	let payload = format!("EHLO {}", "x".repeat(4091));
	send(&mut client, payload.as_bytes()).await;
	expect(&mut client, LONG).await;
	closed(&mut client).await;
	server.healthy().await;
}
