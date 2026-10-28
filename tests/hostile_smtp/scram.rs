//! SCRAM over SMTP on the real listener, over TLS.
//!
//! The last round of the exchange is the one that goes wrong in the
//! field: the server-final cannot ride on the `235` (SMTP has no room
//! for the SASL "additional data with a successful outcome", RFC 4954
//! §4), so it travels as a `334` challenge and the client answers with
//! the empty line. These tests drive that dialogue over a socket, with
//! the framing the way a real client frames it, and check that a line
//! other than the empty one leaves the session unauthenticated.

use std::collections::HashMap;
use std::num::NonZeroU32;

use base64::Engine;
use epistle::smtp::directory::Directory;
use epistle::smtp::scram::{ScramCredentials, ScramStored};
use ring::{digest, hmac, pbkdf2};
use tokio::io::{AsyncRead, AsyncWrite};

use super::harness::*;
use super::tls::Tls;

const PASSWORD: &str = "HostileFixture37!Valid";
/// The salt of the fixture verifier: fixed so the client can derive the
/// same proof the server expects.
const SALT: &[u8] = b"hostile-fixture-16";

/// The fixture directory: the `tester` account with a password hash and
/// a SCRAM verifier.
fn scram_directory() -> Directory {
	let stored = ScramStored::from_credentials(&ScramCredentials::derive(PASSWORD, SALT, 4096));
	directory()
		.with_password_hashes(HashMap::from([(
			"tester".to_string(),
			epistle::smtp::auth::hash_password(PASSWORD).expect("fixture password hash"),
		)]))
		.with_scram([("tester".to_string(), stored)])
}

/// The client-final for the server-first the server sent, proof
/// included.
fn client_final(server_first: &str) -> String {
	let salt_field = server_first
		.split(',')
		.find_map(|field| field.strip_prefix("s="))
		.expect("s= in server-first");
	let salt = base64::engine::general_purpose::STANDARD
		.decode(salt_field)
		.expect("base64 salt");
	let iterations: u32 = server_first
		.split(',')
		.find_map(|field| field.strip_prefix("i="))
		.expect("i= in server-first")
		.parse()
		.expect("iteration count");
	let combined_nonce = server_first
		.split(',')
		.find_map(|field| field.strip_prefix("r="))
		.expect("r= in server-first");
	let without_proof = format!("c=biws,r={combined_nonce}");
	let auth_message = format!("n=tester,r=CN,{server_first},{without_proof}");

	let mut salted = [0u8; 32];
	pbkdf2::derive(
		pbkdf2::PBKDF2_HMAC_SHA256,
		NonZeroU32::new(iterations).unwrap(),
		&salt,
		PASSWORD.as_bytes(),
		&mut salted,
	);
	let client_key = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &salted), b"Client Key");
	let stored_key = digest::digest(&digest::SHA256, client_key.as_ref());
	let client_sig = hmac::sign(
		&hmac::Key::new(hmac::HMAC_SHA256, stored_key.as_ref()),
		auth_message.as_bytes(),
	);
	let proof: Vec<u8> = client_key
		.as_ref()
		.iter()
		.zip(client_sig.as_ref())
		.map(|(a, b)| a ^ b)
		.collect();
	format!(
		"{without_proof},p={}",
		base64::engine::general_purpose::STANDARD.encode(&proof)
	)
}

/// The payload of a `334 <base64>` reply, decoded.
async fn challenge<S: AsyncRead + Unpin>(stream: &mut S) -> String {
	let reply = line(stream)
		.await
		.expect("challenge reply")
		.expect("challenge");
	let payload = reply.trim_start_matches("334 ").trim_end().to_string();
	let raw = base64::engine::general_purpose::STANDARD
		.decode(payload)
		.expect("base64 challenge");
	String::from_utf8(raw).expect("utf8 challenge")
}

/// The whole exchange up to the server-final challenge: the reply is the
/// decoded server-final.
async fn at_server_final<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> String {
	send(stream, b"AUTH SCRAM-SHA-256\r\n").await;
	expect(stream, "334 \r\n").await;
	let client_first = base64::engine::general_purpose::STANDARD.encode("n,,n=tester,r=CN");
	send(stream, format!("{client_first}\r\n").as_bytes()).await;
	let server_first = challenge(stream).await;
	let final_message = client_final(&server_first);
	send(
		stream,
		format!(
			"{}\r\n",
			base64::engine::general_purpose::STANDARD.encode(final_message)
		)
		.as_bytes(),
	)
	.await;
	challenge(stream).await
}

/// The exchange closes with the `235` once the client acknowledges the
/// server-final with the empty line.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scram_authenticates_when_the_client_acknowledges_the_server_final() {
	if !super::enabled() {
		return;
	}
	let tls = Tls::new();
	let server = Harness::with_directory(scram_directory(), |s| tls.server(s)).await;
	let mut client = tls.connect(&server).await;

	let server_final = at_server_final(&mut client).await;
	assert!(
		server_final.starts_with("v="),
		"the challenge must carry the server-final, got {server_final}"
	);

	// The acknowledgement: the empty line.
	send(&mut client, b"\r\n").await;
	expect(&mut client, "235 2.7.0 authentication successful\r\n").await;
	quit(&mut client).await;
	server.healthy().await;
}

/// A line other than the empty one in the last round is refused and
/// leaves the session unauthenticated: the mail never goes out.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_line_other_than_the_empty_one_leaves_the_session_unauthenticated() {
	if !super::enabled() {
		return;
	}
	let tls = Tls::new();
	let server = Harness::with_directory(scram_directory(), |s| tls.server(s)).await;
	let mut client = tls.connect(&server).await;

	let _server_final = at_server_final(&mut client).await;
	send(&mut client, b"Tk9PUA==\r\n").await;
	expect(&mut client, "501 5.5.2 invalid authentication response\r\n").await;
	// The session is still open but not authenticated: a relay to a
	// foreign domain is refused, so the session never got in.
	send(&mut client, b"MAIL FROM:<sender@remote.test>\r\n").await;
	expect(&mut client, "250 2.0.0 ok\r\n").await;
	send(&mut client, b"RCPT TO:<someone@foreign.test>\r\n").await;
	expect(&mut client, "550 5.7.1 relaying denied\r\n").await;
	quit(&mut client).await;
	assert!(
		server.sink.messages().is_empty(),
		"an unauthenticated session must not deliver anything"
	);
	server.healthy().await;
}
