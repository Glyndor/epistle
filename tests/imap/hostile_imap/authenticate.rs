//! `AUTHENTICATE` on the wire: the SASL exchange has its own parser, so its inputs are
//! hostile ones that `LOGIN` never carries: bad base64, an identity that is not the
//! login, a cancelled exchange, a mechanism that does not exist, a line far beyond any
//! credential, and a run of wrong answers. A refusal is a tagged `NO` or `BAD`, or a
//! closed connection; a sign-in is never one of the outcomes.

use base64::Engine;

use super::harness::*;

const BASE64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

fn plain(identity: &str, login: &str, secret: &str) -> String {
	BASE64.encode(format!("{identity}\0{login}\0{secret}"))
}

/// Send `bytes` on a fresh encrypted connection, answer each `+` continuation with
/// `follow_up`, and read until a tagged reply or the end of the connection. Returns the
/// tagged reply, or `None` when the server closed. Panics on a sign-in.
async fn attempt(server: &Harness, bytes: &[u8], follow_up: Option<&[u8]>) -> Option<String> {
	let mut client = server.encrypted().await;
	// A server that has already closed is a refusal, so a failed write is one too.
	if tokio::time::timeout(
		IO_DEADLINE,
		tokio::io::AsyncWriteExt::write_all(&mut client, bytes),
	)
	.await
	.expect("write deadline")
	.is_err()
	{
		return None;
	}
	for _ in 0..6 {
		match line(&mut client).await {
			Ok(Some(reply)) if reply.starts_with("A1 ") => {
				assert!(!reply.starts_with("A1 OK"), "signed in: {reply}");
				assert!(
					reply.starts_with("A1 NO") || reply.starts_with("A1 BAD"),
					"{reply}"
				);
				return Some(reply);
			}
			Ok(Some(reply)) if reply.starts_with('+') => {
				if let Some(next) = follow_up
					&& tokio::io::AsyncWriteExt::write_all(&mut client, next)
						.await
						.is_err()
				{
					return None;
				}
			}
			Ok(Some(_)) => {}
			Ok(None) | Err(_) => return None,
		}
	}
	None
}

#[tokio::test]
async fn invalid_base64_in_the_initial_response_is_refused() {
	let server = Harness::start(|s| s).await;
	for bad in ["!!!!", "====", "QQ=", "QUJD\u{e9}", "a b c d"] {
		attempt(
			&server,
			format!("A1 AUTHENTICATE PLAIN {bad}\r\n").as_bytes(),
			None,
		)
		.await;
	}
	server.healthy().await;
}

#[tokio::test]
async fn an_identity_that_is_not_the_login_is_refused() {
	let server = Harness::start(|s| s).await;
	for identity in [
		"victim",
		"tester\0extra",
		"../tester",
		"TESTER@other.example",
	] {
		let blob = plain(identity, "tester", &PASSWORD.to_string());
		let outcome = attempt(
			&server,
			format!("A1 AUTHENTICATE PLAIN {blob}\r\n").as_bytes(),
			None,
		)
		.await;
		assert!(
			outcome
				.as_deref()
				.is_none_or(|reply| !reply.starts_with("A1 OK")),
			"{identity:?}: {outcome:?}"
		);
	}
	server.healthy().await;
}

#[tokio::test]
async fn a_cancelled_exchange_and_an_unknown_mechanism_are_refused() {
	let server = Harness::start(|s| s).await;
	attempt(&server, b"A1 AUTHENTICATE PLAIN\r\n", Some(b"*\r\n")).await;
	for mechanism in ["NOSUCH", "plain\u{0}", "X-GSSAPI", "PLAIN SCRAM-SHA-256"] {
		attempt(
			&server,
			format!("A1 AUTHENTICATE {mechanism}\r\n").as_bytes(),
			None,
		)
		.await;
	}
	server.healthy().await;
}

#[tokio::test]
async fn a_credential_line_far_beyond_any_credential_is_cut_not_buffered() {
	let server = Harness::start(|s| s).await;
	let huge = format!("{}\r\n", "QUJD".repeat(256 * 1024));
	attempt(&server, b"A1 AUTHENTICATE PLAIN\r\n", Some(huge.as_bytes())).await;
	server.healthy().await;
}

#[tokio::test]
async fn wrong_answers_close_the_connection_after_a_few() {
	let server = Harness::start(|s| s).await;
	let mut client = server.encrypted().await;
	let blob = plain("", "tester", "wrong-password-1A!");
	let mut closed_after = None;
	for attempt in 1..=10 {
		let command = format!("A{attempt} AUTHENTICATE PLAIN {blob}\r\n");
		if tokio::io::AsyncWriteExt::write_all(&mut client, command.as_bytes())
			.await
			.is_err()
		{
			closed_after = Some(attempt);
			break;
		}
		match line(&mut client).await {
			Ok(Some(reply)) => assert!(!reply.contains(" OK"), "{reply}"),
			Ok(None) | Err(_) => {
				closed_after = Some(attempt);
				break;
			}
		}
	}
	assert!(closed_after.is_some_and(|n| n <= 6), "{closed_after:?}");
	server.healthy().await;
}
