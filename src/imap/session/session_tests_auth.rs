//! IMAP AUTHENTICATE (SASL) tests.

use super::*;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

fn unauth(dir: &std::path::Path) -> Session {
	Session::new("mail.example.org", dir.to_path_buf(), directory())
}

/// Build a directory with the alice account and the supplied ban store
/// attached. Used by [`imap_login_records_the_peer_ip`] to assert the
/// IMAP session routes the LOGIN attempt through
/// [`crate::smtp::directory::Directory::authenticate_with_ip`] with the
/// peer IP the network layer recorded.
fn directory_with_ban_store(
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

/// A 32-byte stand-in for the tls-server-end-point certificate hash.
const CERT_HASH: &[u8] = b"0123456789abcdef0123456789abcdef";

#[test]
fn authenticate_scram_plus_succeeds() {
	use ring::{digest, hmac, pbkdf2};
	use std::num::NonZeroU32;

	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = Session::new(
		"mail.example.org",
		dir.path().to_path_buf(),
		scram_directory(),
	)
	.with_scram_nonce("SN")
	.with_channel_binding(CERT_HASH.to_vec());

	let header = "p=tls-server-end-point,,";
	let output = session.command_line(&format!(
		"a1 AUTHENTICATE SCRAM-SHA-256-PLUS {}",
		B64.encode(format!("{header}n=alice,r=CN"))
	));
	assert!(output.collect_auth, "bound -PLUS requests a continuation");

	// c = base64(gs2-header || tls-server-end-point).
	let mut cbind = header.as_bytes().to_vec();
	cbind.extend_from_slice(CERT_HASH);
	let without_proof = format!("c={},r=CNSN", B64.encode(&cbind));
	let salt = b"saltsalt";
	let server_first = format!("r=CNSN,s={},i=4096", B64.encode(salt));
	let auth_message = format!("n=alice,r=CN,{server_first},{without_proof}");
	let mut salted = [0u8; 32];
	pbkdf2::derive(
		pbkdf2::PBKDF2_HMAC_SHA256,
		NonZeroU32::new(4096).unwrap(),
		salt,
		b"secret",
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
	let client_final = format!("{without_proof},p={}", B64.encode(&proof));
	let response = text(&session.auth_response(&B64.encode(&client_final)));
	assert!(response.contains("a1 OK"), "{response}");
}

#[test]
fn authenticate_scram_plus_unavailable_without_binding() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = Session::new(
		"mail.example.org",
		dir.path().to_path_buf(),
		scram_directory(),
	);
	// No certificate hash configured → -PLUS is not offered.
	let response = text(&session.command_line(&format!(
		"a1 AUTHENTICATE SCRAM-SHA-256-PLUS {}",
		B64.encode("p=tls-server-end-point,,n=alice,r=CN")
	)));
	assert!(response.contains("a1 NO"), "{response}");
}

#[test]
fn authenticate_scram_rejects_downgrade_when_bound() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = Session::new(
		"mail.example.org",
		dir.path().to_path_buf(),
		scram_directory(),
	)
	.with_scram_nonce("SN")
	.with_channel_binding(CERT_HASH.to_vec());
	// Plain SCRAM with `y,,` on a link that offers -PLUS is a downgrade.
	let response = text(&session.command_line(&format!(
		"a1 AUTHENTICATE SCRAM-SHA-256 {}",
		B64.encode("y,,n=alice,r=CN")
	)));
	assert!(response.contains("a1 NO"), "{response}");
}

#[test]
fn authenticate_external_with_client_cert() {
	let tmp = tempfile::tempdir().expect("tempdir");
	let mut session = unauth(tmp.path());
	// The TLS layer recorded a verified certificate identity.
	session.set_client_identity(Some("alice@example.org".to_string()));
	let caps = text(&session.command_line("a CAPABILITY"));
	assert!(caps.contains("AUTH=EXTERNAL"), "{caps}");
	// Empty initial response (`=`) means "use the certificate identity".
	let out = text(&session.command_line("b AUTHENTICATE EXTERNAL ="));
	assert!(out.contains("b OK"), "{out}");
}

#[test]
fn authenticate_external_unavailable_without_client_cert() {
	let tmp = tempfile::tempdir().expect("tempdir");
	let mut session = unauth(tmp.path());
	let caps = text(&session.command_line("a CAPABILITY"));
	assert!(!caps.contains("AUTH=EXTERNAL"), "{caps}");
	let out = text(&session.command_line("b AUTHENTICATE EXTERNAL ="));
	assert!(out.contains("b NO"), "{out}");
}

#[test]
fn authenticate_external_rejects_mismatched_authzid() {
	let tmp = tempfile::tempdir().expect("tempdir");
	let mut session = unauth(tmp.path());
	session.set_client_identity(Some("alice@example.org".to_string()));
	// Requesting to act as another user fails.
	let authzid = B64.encode("bob@example.org");
	let out = text(&session.command_line(&format!("b AUTHENTICATE EXTERNAL {authzid}")));
	assert!(out.contains("b NO"), "{out}");
}

/// An IMAP LOGIN attempt routes through the directory's
/// `authenticate_with_ip` with the peer IP the network layer recorded
/// on `set_peer_ip`. The test sets up a [`FakeBanStore`], drives LOGIN
/// with a wrong password, and asserts the fake recorded a
/// `record_failure` call keyed on `ip:<peer>`; the subject the
/// directory builds for the peer IP. The directory is the only place
/// that builds `ip:<peer>` strings, so a count of one on the right
/// subject is the proof the peer IP reached the ban path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn imap_login_records_the_peer_ip() {
	use crate::antispam::bans::BanPolicy;
	use crate::antispam::bans::tests::FakeBanStore;

	let tmp = tempfile::tempdir().expect("tempdir");
	let ban_store = std::sync::Arc::new(FakeBanStore::new(BanPolicy::default()));
	let peer: std::net::IpAddr = "203.0.113.20".parse().expect("peer");
	let mut session = Session::new(
		"mail.example.org",
		tmp.path().to_path_buf(),
		directory_with_ban_store(ban_store.clone()),
	);
	// The network layer sets the peer IP before the command loop runs.
	session.set_peer_ip(Some(peer));
	let out = text(&session.command_line("a LOGIN alice wrong"));
	assert!(out.contains("a NO"), "{out}");

	assert!(
		ban_store.call_count("record_failure") >= 2,
		"ban store recorded {} failure(s); expected at least two (IP and account)",
		ban_store.call_count("record_failure")
	);
	assert!(
		ban_store.failure_count("ip:203.0.113.20", 0) >= 1,
		"ban store did not record a failure for ip:203.0.113.20"
	);
	assert!(
		ban_store.failure_count("account:alice", 0) >= 1,
		"ban store did not record a failure for account:alice"
	);
}
