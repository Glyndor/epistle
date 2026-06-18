//! IMAP AUTHENTICATE (SASL) tests.

use super::*;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

fn unauth(dir: &std::path::Path) -> Session {
	Session::new("mail.example.org", dir.to_path_buf(), directory())
}

#[test]
fn authenticate_plain_initial_response() {
	let tmp = tempfile::tempdir().expect("tempdir");
	let mut session = unauth(tmp.path());
	let ir = B64.encode("\0alice\0secret");
	let out = text(&session.command_line(&format!("a AUTHENTICATE PLAIN {ir}")));
	assert!(out.contains("a OK"), "{out}");
}

#[test]
fn authenticate_plain_continuation_and_bad_credentials() {
	let tmp = tempfile::tempdir().expect("tempdir");
	let mut session = unauth(tmp.path());
	// No initial response: server sends an empty continuation.
	let out = text(&session.command_line("a AUTHENTICATE PLAIN"));
	assert!(out.starts_with("+ "), "{out}");
	let out = text(&session.auth_response(&B64.encode("\0alice\0wrong")));
	assert!(out.contains("a NO"), "{out}");
}

#[test]
fn authenticate_login_flow() {
	let tmp = tempfile::tempdir().expect("tempdir");
	let mut session = unauth(tmp.path());
	let out = text(&session.command_line("a AUTHENTICATE LOGIN"));
	assert!(
		out.contains("VXNlcm5hbWU6"),
		"expected Username: prompt, {out}"
	);
	let out = text(&session.auth_response(&B64.encode("alice")));
	assert!(
		out.contains("UGFzc3dvcmQ6"),
		"expected Password: prompt, {out}"
	);
	let out = text(&session.auth_response(&B64.encode("secret")));
	assert!(out.contains("a OK"), "{out}");
}

#[test]
fn authenticate_login_rejects_bad_base64_username() {
	let tmp = tempfile::tempdir().expect("tempdir");
	let mut session = unauth(tmp.path());
	session.command_line("a AUTHENTICATE LOGIN");
	let out = text(&session.auth_response("!!!not-base64"));
	assert!(out.contains("a NO"), "{out}");
}

#[test]
fn authenticate_unsupported_mechanism() {
	let tmp = tempfile::tempdir().expect("tempdir");
	let mut session = unauth(tmp.path());
	let out = text(&session.command_line("a AUTHENTICATE CRAM-MD5"));
	assert!(out.contains("a NO"), "{out}");
}

#[test]
fn authenticate_can_be_cancelled() {
	let tmp = tempfile::tempdir().expect("tempdir");
	let mut session = unauth(tmp.path());
	session.command_line("a AUTHENTICATE PLAIN");
	let out = text(&session.auth_response("*"));
	assert!(out.contains("a BAD"), "{out}");
}

#[test]
fn auth_response_without_pending_is_rejected() {
	let tmp = tempfile::tempdir().expect("tempdir");
	let mut session = unauth(tmp.path());
	let out = text(&session.auth_response("anything"));
	assert!(out.contains("BAD"), "{out}");
}

#[test]
fn authenticate_when_already_authenticated_is_bad() {
	let tmp = tempfile::tempdir().expect("tempdir");
	let mut session = unauth(tmp.path());
	session.command_line(&format!(
		"a AUTHENTICATE PLAIN {}",
		B64.encode("\0alice\0secret")
	));
	let out = text(&session.command_line("b AUTHENTICATE PLAIN"));
	assert!(out.contains("b BAD"), "{out}");
}
