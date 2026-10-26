//! OAUTHBEARER and XOAUTH2 without a SASL-IR initial response (RFC 3501 6.2.2,
//! RFC 4959) and the RFC 7628 error challenge.

use super::*;
use crate::smtp::directory::gate_fixture::*;
use crate::test_fixtures as fixtures;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

fn session(dir: &std::path::Path) -> (Session, String) {
	let (verifier, pair, rng) = verifier_and_key();
	let response = bearer_response(&pair, &rng, "alice@example.org");
	let session = Session::new("mail.example.org", dir.to_path_buf(), gate_directory_arc())
		.with_scram_nonce(fixtures::nonce())
		.with_oauth(Some(verifier));
	(session, response)
}

const MECHANISMS: [&str; 2] = ["OAUTHBEARER", "XOAUTH2"];

#[test]
fn a_bearer_without_an_initial_response_gets_an_empty_continuation() {
	for mechanism in MECHANISMS {
		let dir = tempfile::tempdir().expect("tempdir");
		let (mut session, response) = session(dir.path());
		let first = session.command_line(&format!("a AUTHENTICATE {mechanism}"));
		assert_eq!(text(&first), "+ \r\n", "{mechanism}");
		assert!(first.collect_auth, "{mechanism}");
		let done = text(&session.auth_response(&response));
		assert!(
			done.contains("a OK AUTHENTICATE completed"),
			"{mechanism}: {done}"
		);
		assert_eq!(session.account(), Some(OPEN), "{mechanism}");
	}
}

#[test]
fn cancelling_a_bearer_exchange_answers_bad() {
	for mechanism in MECHANISMS {
		let dir = tempfile::tempdir().expect("tempdir");
		let (mut session, _) = session(dir.path());
		session.command_line(&format!("a AUTHENTICATE {mechanism}"));
		let done = text(&session.auth_response("*"));
		assert!(done.contains("a BAD authentication cancelled"), "{done}");
		assert_eq!(session.account(), None);
	}
}

#[test]
fn a_rejected_token_gets_the_error_challenge_then_no() {
	for mechanism in MECHANISMS {
		for with_initial in [true, false] {
			let dir = tempfile::tempdir().expect("tempdir");
			let (mut session, _) = session(dir.path());
			let bad = B64.encode("n,a=alice@example.org,\x01auth=Bearer not.a.jwt\x01\x01");
			let challenge = if with_initial {
				session.command_line(&format!("a AUTHENTICATE {mechanism} {bad}"))
			} else {
				session.command_line(&format!("a AUTHENTICATE {mechanism}"));
				session.auth_response(&bad)
			};
			assert!(challenge.collect_auth, "{mechanism} {with_initial}");
			let body = text(&challenge);
			let json = body.strip_prefix("+ ").expect("a continuation").trim();
			let json = String::from_utf8(B64.decode(json).expect("base64")).expect("utf8");
			assert_eq!(json, r#"{"status":"invalid_token"}"#);
			let done = text(&session.auth_response("AQ=="));
			assert_eq!(done, "a NO authentication failed\r\n", "{mechanism}");
			assert_eq!(session.account(), None);
		}
	}
}

#[test]
fn cancelling_after_the_error_challenge_still_counts_as_a_failure() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (mut session, _) = session(dir.path());
	let bad = B64.encode("n,a=alice@example.org,\x01auth=Bearer not.a.jwt\x01\x01");
	for round in 0..2 {
		session.command_line(&format!("a AUTHENTICATE OAUTHBEARER {bad}"));
		let done = text(&session.auth_response("*"));
		assert_eq!(done, "a NO authentication failed\r\n", "round {round}");
	}
	// The third failure closes the connection without another challenge.
	let last = session.command_line(&format!("a AUTHENTICATE OAUTHBEARER {bad}"));
	assert!(!last.collect_auth);
	assert!(
		text(&last).contains("* BYE too many failures"),
		"{}",
		text(&last)
	);
}
