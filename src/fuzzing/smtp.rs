//! The SMTP adapters: the SASL exchange, the reply of a remote server and the chunked message.

use super::common::INPUT_CAP;
use super::common::floor_char_boundary;
use super::scram_client;

/// The reply of a remote SMTP server as the outbound client frames it: where
/// the first complete reply ends, for any bytes a hostile server sends.
pub fn smtp_reply(raw: &[u8]) {
	let raw = &raw[..raw.len().min(INPUT_CAP)];
	std::hint::black_box(crate::queue::client::complete_reply_for_fuzzing(raw));
}

/// The SASL messages a client sends before it is logged in: PLAIN, the
/// OAUTHBEARER and XOAUTH2 initial response of SMTP and of IMAP, and a
/// SCRAM-SHA-256 exchange under each channel binding policy. The first line is
/// the client-first message and the rest the client-final one.
///
/// The account is made once per process from random bytes. Besides the
/// client's own final message, the exchange is finished the way a client that
/// knows the password would: it must succeed with the nonce the server sent,
/// and fail with any other nonce or a proof that is off by one bit. A final
/// message the server accepts must carry the proof only the password gives.
pub fn sasl_exchange(input: &str) {
	use crate::smtp::scram::{ChannelBinding, ScramError, ScramServer, username_of};
	let input = &input[..floor_char_boundary(input, INPUT_CAP)];
	let _ = crate::smtp::auth::parse_plain(input);
	std::hint::black_box(crate::smtp::session::parse_bearer(input));
	std::hint::black_box(crate::imap::session::parse_bearer(input));
	let (first, last) = input.split_once('\n').unwrap_or((input, ""));
	let account = scram_client::account();
	let username = username_of(first);
	for binding in [
		ChannelBinding::Unsupported,
		ChannelBinding::Supported,
		ChannelBinding::Required(account.end_point.clone()),
	] {
		let mut server =
			ScramServer::new(account.nonce.as_str()).with_channel_binding(binding.clone());
		let Ok((user, server_first)) = server.first(first, &account.credentials) else {
			continue;
		};
		assert_eq!(Some(user), username, "first and username_of disagree");
		let flag = first.split(',').next().unwrap_or("");
		match &binding {
			ChannelBinding::Supported => assert_eq!(flag, "n"),
			ChannelBinding::Required(_) => assert_eq!(flag, "p=tls-server-end-point"),
			ChannelBinding::Unsupported => {}
		}
		let exchange = scram_client::Exchange::new(account, first, &server_first, &binding);
		if let Ok(server_final) = server.finish(last, &account.credentials) {
			let proof = last.split(',').find_map(|field| field.strip_prefix("p="));
			let without_proof = last.rsplit_once(",p=").map(|(head, _)| head);
			let expected = without_proof.map(|head| exchange.proof(head));
			// The assertions name what failed and print no proof or key.
			assert!(
				proof.map(str::to_string) == expected,
				"a proof nobody signed was accepted"
			);
			assert!(
				server_final == exchange.server_final(without_proof.unwrap_or("")),
				"the server signature is not the one its key gives"
			);
		}
		let Some(combined) = server_first
			.strip_prefix("r=")
			.and_then(|rest| rest.split(',').next())
		else {
			panic!("server-first does not open with the nonce");
		};
		let honest = exchange.without_proof(combined);
		assert!(
			server.finish(&exchange.signed(&honest), &account.credentials)
				== Ok(exchange.server_final(&honest)),
			"the password did not open the account",
		);
		let tampered = format!("{honest},p={}", exchange.flipped(&honest));
		assert!(
			server.finish(&tampered, &account.credentials) == Err(ScramError::AuthenticationFailed),
			"a proof off by one bit was accepted",
		);
		if let Some(echoed) = last.split(',').next()
			&& echoed != combined
		{
			let replayed = exchange.without_proof(echoed);
			assert!(
				server.finish(&exchange.signed(&replayed), &account.credentials)
					== Err(ScramError::Malformed),
				"a nonce the server did not send was accepted",
			);
		}
	}
}

/// The message size limit of a BDAT run: small, so the oversize path is
/// reachable from short inputs.
const BDAT_MAX_SIZE: usize = 256;

/// A BDAT chunked message as a client sends it, read through the SMTP
/// session: the chunks of the message, and the flag that marks the last
/// one.
///
/// The session is the one a client talks to: it answers the commands, reads
/// the chunks and hands the message over. The `directory` resolves the
/// recipients, `sender` and `recipient` are the envelope the client names,
/// and every chunk is one the client sends, with the flag that says whether
/// it is the last one.
///
/// # Panics
///
/// When the sequence hands over more than one message, or a message whose
/// body is not the octets of the chunks that were sent.
pub fn smtp_bdat(
	directory: std::sync::Arc<crate::smtp::directory::Directory>,
	sender: &str,
	recipient: &str,
	chunks: &[(Vec<u8>, bool)],
) {
	use crate::smtp::session::{Action, Session};

	let mut session = Session::new("mx.example.org")
		.with_directory(directory)
		.with_max_message_size(BDAT_MAX_SIZE);
	session.greeting();
	session.command_line("EHLO client.test");
	session.command_line(&format!("MAIL FROM:<{sender}>"));
	session.command_line(&format!("RCPT TO:<{recipient}>"));
	// The octets the session kept, and the messages it handed over.
	let mut body: Vec<u8> = Vec::new();
	let mut delivered = 0usize;
	for (chunk, last) in chunks {
		let line = format!("BDAT {}{}", chunk.len(), if *last { " LAST" } else { "" });
		match session.command_line(&line) {
			Action::CollectChunk { size, last } => {
				let bytes = &chunk[..size.min(chunk.len())];
				match session.bdat_chunk(bytes, last) {
					Action::Deliver(_, message) => {
						delivered += 1;
						assert_eq!(delivered, 1, "more than one message in a chunk sequence");
						body.extend_from_slice(bytes);
						assert_eq!(
							message.data, body,
							"the message is not the chunks that were sent"
						);
						assert_eq!(
							message.reverse_path, sender,
							"the sender is not the one sent"
						);
						assert_eq!(
							message.recipients.len(),
							1,
							"the message has other recipients"
						);
						assert!(
							message.recipients[0].eq_ignore_ascii_case(recipient),
							"the recipient is not the one sent"
						);
					}
					// The chunk was kept.
					Action::Continue(reply) if reply.code() == 250 => {
						body.extend_from_slice(bytes);
					}
					// A refused chunk ends the transaction, and the body it
					// had goes back with it.
					Action::Continue(_) => body.clear(),
					// The connection is over.
					Action::Close(_) => break,
					_ => {}
				}
			}
			// A refused chunk is read and thrown away.
			Action::DiscardChunk { .. } => body.clear(),
			// The connection is over.
			Action::Close(_) => break,
			_ => {}
		}
	}
}
