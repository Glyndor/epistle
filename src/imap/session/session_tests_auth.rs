//! IMAP AUTHENTICATE (SASL) tests.

use super::*;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

pub(super) fn unauth(dir: &std::path::Path) -> Session {
	Session::new("mail.example.org", dir.to_path_buf(), directory())
}

/// Build a directory with the alice account and the supplied ban store
/// attached. Used by [`imap_login_records_the_peer_ip`] to assert the
/// IMAP session routes the LOGIN attempt through
/// [`crate::smtp::directory::Directory::authenticate_with_ip`] with the
/// peer IP the network layer recorded.
pub(super) fn directory_with_ban_store(
	ban_store: std::sync::Arc<dyn crate::antispam::bans::BanStore>,
) -> Arc<Directory> {
	Arc::new(
		Directory::new(
			["example.org".to_string()],
			[("alice@example.org".to_string(), "alice".to_string())],
		)
		.with_password_hashes(std::collections::HashMap::from([(
			"alice".to_string(),
			crate::smtp::auth::tests::hash("secret"),
		)]))
		.with_ban_store(ban_store),
	)
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
