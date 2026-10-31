//! The INFO line that records an authentication attempt on an SMTP
//! session.
//!
//! The password path (SASL PLAIN, AUTH LOGIN) writes the audit channel
//! `epistle::auth`, which carries the same facts. The mechanisms that
//! never reach the directory's password check — SCRAM, OAuth and SASL
//! EXTERNAL — wrote nothing at the default level, so an attempt on them
//! was invisible in the log: a failed SCRAM exchange left a warning
//! without the protocol, and a successful one left nothing at all.
//!
//! The line carries no personal data: the account appears as its log
//! pseudonym, and a refused attempt does not name an account at all.

use tracing_subscriber::layer::SubscriberExt;

use super::super::scram::tests_scram::{b64, reply_code, scram_session};
use super::super::scram::tests_scram_final::at_server_final;
use super::tests_oauth::{auth_directory, bearer_response, verifier_and_key};
use super::*;
use crate::cli::trace::capture::CapturedEvent;

/// Run `f` with a subscriber that captures every event, and return the
/// events it recorded.
fn capture<F: FnOnce()>(f: F) -> Vec<CapturedEvent> {
	crate::cli::trace::capture::keep_callsites_live();
	let capture = crate::cli::trace::capture::Capture::default();
	let events = capture.events.clone();
	let _guard =
		tracing::subscriber::set_default(tracing_subscriber::registry().with(capture.clone()));
	f();
	std::mem::take(&mut *events.lock().expect("capture"))
}

/// The lines about an authentication attempt.
fn attempts(captured: &[CapturedEvent]) -> Vec<&CapturedEvent> {
	captured
		.iter()
		.filter(|event| event.fields.contains_key("mechanism"))
		.collect()
}

/// A SCRAM exchange that succeeds leaves one INFO line at the default
/// level, with the account it authenticated as its log pseudonym.
#[test]
fn a_successful_scram_exchange_leaves_one_info_line() {
	let (mut session, _client, _server_final) = at_server_final();
	let captured = capture(|| {
		let action = session.auth_line("");
		assert_eq!(reply_code(&action), 235);
	});
	let lines = attempts(&captured);
	assert_eq!(
		lines.len(),
		1,
		"expected exactly one line about the authentication attempt"
	);
	assert_eq!(
		lines[0].level,
		tracing::Level::INFO,
		"the line must be at the default level"
	);
	assert_eq!(
		lines[0].fields.get("result").map(String::as_str),
		Some("succeeded")
	);
	assert_eq!(
		lines[0].fields.get("mechanism").map(String::as_str),
		Some("SCRAM")
	);
	assert_eq!(
		lines[0].fields.get("log_id").map(String::as_str),
		Some(crate::log_id::account("alice").as_str()),
		"the line must name the account by its log pseudonym"
	);
}

/// A SCRAM exchange that is refused leaves one INFO line too, and it
/// names no account: the wire answer does not say which account the
/// client tried to be either.
#[test]
fn a_refused_scram_exchange_leaves_one_info_line() {
	let mut session = scram_session(true);
	let captured = capture(|| {
		let action = session.command_line("AUTH SCRAM-SHA-256 !!!not-base64");
		assert_eq!(reply_code(&action), 535);
	});
	let lines = attempts(&captured);
	assert_eq!(
		lines.len(),
		1,
		"expected exactly one line about the authentication attempt"
	);
	assert_eq!(lines[0].level, tracing::Level::INFO);
	assert_eq!(
		lines[0].fields.get("result").map(String::as_str),
		Some("failed")
	);
	assert_eq!(
		lines[0].fields.get("mechanism").map(String::as_str),
		Some("SCRAM")
	);
	assert_eq!(
		lines[0].fields.get("log_id").map(String::as_str),
		Some("unknown"),
		"a refused attempt must not name the account it tried to be"
	);
}

/// An OAuth exchange that succeeds leaves one INFO line at the default
/// level.
#[test]
fn a_successful_oauth_exchange_leaves_one_info_line() {
	let (verifier, pair, rng) = verifier_and_key();
	let response = bearer_response(&pair, &rng, "alice@example.org");
	let mut session = Session::new("mail.example.org")
		.with_directory(auth_directory())
		.with_tls_active()
		.with_oauth(verifier);
	session.command_line("EHLO client.example.org");
	let captured = capture(|| {
		let action = session.command_line(&format!("AUTH OAUTHBEARER {response}"));
		assert_eq!(reply_code(&action), 235);
	});
	let lines = attempts(&captured);
	assert_eq!(
		lines.len(),
		1,
		"expected exactly one line about the authentication attempt"
	);
	assert_eq!(lines[0].level, tracing::Level::INFO);
	assert_eq!(
		lines[0].fields.get("result").map(String::as_str),
		Some("succeeded")
	);
	assert_eq!(
		lines[0].fields.get("mechanism").map(String::as_str),
		Some("OAuth")
	);
	assert_eq!(
		lines[0].fields.get("log_id").map(String::as_str),
		Some(crate::log_id::account("alice").as_str())
	);
}

/// An OAuth exchange that is refused leaves one INFO line, and it names
/// no account.
#[test]
fn a_refused_oauth_exchange_leaves_one_info_line() {
	let (verifier, _pair, _rng) = verifier_and_key();
	let mut session = Session::new("mail.example.org")
		.with_directory(auth_directory())
		.with_tls_active()
		.with_oauth(verifier);
	session.command_line("EHLO client.example.org");
	let captured = capture(|| {
		let action = session.command_line(&format!(
			"AUTH OAUTHBEARER {}",
			b64("n,a=alice@example.org,\x01auth=Bearer nope\x01\x01")
		));
		assert_eq!(reply_code(&action), 535);
	});
	let lines = attempts(&captured);
	assert_eq!(
		lines.len(),
		1,
		"expected exactly one line about the authentication attempt"
	);
	assert_eq!(lines[0].level, tracing::Level::INFO);
	assert_eq!(
		lines[0].fields.get("result").map(String::as_str),
		Some("failed")
	);
	assert_eq!(
		lines[0].fields.get("log_id").map(String::as_str),
		Some("unknown"),
		"a refused attempt must not name the account it tried to be"
	);
}

/// A SASL EXTERNAL exchange that succeeds leaves one INFO line at the
/// default level: the certificate identity resolves to an account, and
/// the line names it by its log pseudonym.
#[test]
fn a_successful_external_exchange_leaves_one_info_line() {
	let mut session = Session::new("mail.example.org")
		.with_directory(auth_directory())
		.with_tls_active();
	session.set_client_identity(Some("alice@example.org".to_string()));
	session.command_line("EHLO client.example.org");
	let captured = capture(|| {
		let action = session.command_line("AUTH EXTERNAL");
		assert_eq!(reply_code(&action), 334);
		let action = session.auth_line("");
		assert_eq!(reply_code(&action), 235);
	});
	let lines = attempts(&captured);
	assert_eq!(
		lines.len(),
		1,
		"expected exactly one line about the authentication attempt"
	);
	assert_eq!(lines[0].level, tracing::Level::INFO);
	assert_eq!(
		lines[0].fields.get("result").map(String::as_str),
		Some("succeeded")
	);
	assert_eq!(
		lines[0].fields.get("mechanism").map(String::as_str),
		Some("EXTERNAL")
	);
	assert_eq!(
		lines[0].fields.get("log_id").map(String::as_str),
		Some(crate::log_id::account("alice").as_str())
	);
}

/// A SASL EXTERNAL exchange that is refused leaves one INFO line, and it
/// names no account.
#[test]
fn a_refused_external_exchange_leaves_one_info_line() {
	let mut session = Session::new("mail.example.org")
		.with_directory(auth_directory())
		.with_tls_active();
	// A verified certificate whose identity is not an account here: the
	// exchange is offered and then refused.
	session.set_client_identity(Some("ghost@example.org".to_string()));
	session.command_line("EHLO client.example.org");
	let captured = capture(|| {
		let action = session.command_line("AUTH EXTERNAL");
		assert_eq!(reply_code(&action), 334);
		let action = session.auth_line("");
		assert_eq!(reply_code(&action), 535);
	});
	let lines = attempts(&captured);
	assert_eq!(
		lines.len(),
		1,
		"expected exactly one line about the authentication attempt"
	);
	assert_eq!(lines[0].level, tracing::Level::INFO);
	assert_eq!(
		lines[0].fields.get("result").map(String::as_str),
		Some("failed")
	);
	assert_eq!(
		lines[0].fields.get("mechanism").map(String::as_str),
		Some("EXTERNAL")
	);
	assert_eq!(
		lines[0].fields.get("log_id").map(String::as_str),
		Some("unknown"),
		"a refused attempt must not name the account it tried to be"
	);
}
