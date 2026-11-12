use super::*;
use crate::test_support::fixtures;

#[test]
fn plaintext_session_disables_login_until_starttls() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session =
		Session::new("mail.example.org", dir.path().to_path_buf(), directory()).with_starttls();

	let greeting = text(&session.greeting());
	assert!(greeting.contains("STARTTLS"), "{greeting}");
	assert!(greeting.contains("LOGINDISABLED"), "{greeting}");
	assert!(!greeting.contains("AUTH=PLAIN"), "{greeting}");

	let output = session.command_line(&format!("a1 LOGIN alice {}", fixtures::password()));
	assert!(
		text(&output).contains("PRIVACYREQUIRED"),
		"{}",
		text(&output)
	);

	let output = session.command_line("a2 STARTTLS");
	assert!(output.upgrade_tls);
	assert!(text(&output).contains("a2 OK"), "{}", text(&output));

	session.tls_started();
	let output = session.command_line("a3 CAPABILITY");
	let response = text(&output);
	assert!(!response.contains("STARTTLS"), "{response}");
	assert!(response.contains("AUTH=PLAIN"), "{response}");
	let output = session.command_line(&format!("a4 LOGIN alice {}", fixtures::password()));
	assert!(text(&output).contains("a4 OK"), "{}", text(&output));
}

#[test]
fn namespace_before_auth_returns_bad_with_no_listing() {
	// RFC 2342 / RFC 9051 §6.3.5: NAMESPACE is post-auth. Pre-auth it must
	// fail with BAD/NO and not publish any untagged NAMESPACE response, so
	// a peeking client cannot probe the server's namespace layout before
	// logging in.
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = Session::new("mail.example.org", dir.path().to_path_buf(), directory());
	let output = session.command_line("a1 NAMESPACE");
	let response = text(&output);
	assert_eq!(
		response, "a1 NO not authenticated\r\n",
		"pre-auth NAMESPACE must NOT list anything and MUST refuse the command"
	);
}

#[test]
fn namespace_after_auth_lists_personal_namespace() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	let output = session.command_line("a1 NAMESPACE");
	let response = text(&output);
	assert!(
		response.contains("* NAMESPACE ((\"\" \"/\")) NIL NIL"),
		"{response}"
	);
	assert!(response.contains("a1 OK NAMESPACE completed"), "{response}");
}

#[test]
fn id_hides_server_version_and_accepts_client_params() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = Session::new("mail.example.org", dir.path().to_path_buf(), directory());
	let output = session.command_line("a1 ID (\"name\" \"Thunderbird\" \"version\" \"128\")");
	let response = text(&output);
	let id = response
		.lines()
		.find(|line| line.starts_with("* ID "))
		.unwrap();
	assert_eq!(id, "* ID NIL");
	assert!(
		!id.chars().any(|character| character.is_ascii_digit()),
		"{id}"
	);
	assert!(response.contains("a1 OK ID completed"), "{response}");
	let response = text(&session.command_line("a2 ID NIL"));
	assert_eq!(response, "* ID NIL\r\na2 OK ID completed\r\n");

	let mut session = logged_in(dir.path());
	let response = text(&session.command_line("a3 ID NIL"));
	assert_eq!(response, "* ID NIL\r\na3 OK ID completed\r\n");
}

#[test]
fn capability_advertises_namespace_and_special_use() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = Session::new("mail.example.org", dir.path().to_path_buf(), directory());
	let response = text(&session.command_line("a1 CAPABILITY"));
	assert!(response.contains("NAMESPACE"), "{response}");
	assert!(response.contains("SPECIAL-USE"), "{response}");
	assert!(response.contains("UNSELECT"), "{response}");
	assert!(response.contains("ENABLE"), "{response}");
}

#[test]
fn status_reports_deleted_and_mailboxid() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"one\r\n");
	deliver(dir.path(), b"two\r\n");
	let mut session = logged_in(dir.path());
	session.command_line("a2 SELECT INBOX");
	session.command_line(r"a3 STORE 1 +FLAGS (\Deleted)");
	// STATUS exposes the DELETED count and a stable MAILBOXID (OBJECTID).
	let response = text(&session.command_line("a4 STATUS INBOX (MESSAGES DELETED MAILBOXID)"));
	assert!(response.contains("MESSAGES 2"), "{response}");
	assert!(response.contains("DELETED 1"), "{response}");
	assert!(response.contains("MAILBOXID (M"), "{response}");
}

#[test]
fn quota_reports_storage_usage() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"From: a@b\r\n\r\nsome bytes\r\n");
	let mut session = logged_in(dir.path());

	let response = text(&session.command_line("a2 GETQUOTAROOT INBOX"));
	assert!(
		response.contains("* QUOTAROOT \"INBOX\" \"\""),
		"{response}"
	);
	assert!(response.contains("* QUOTA \"\" (STORAGE "), "{response}");
	assert!(
		response.contains("a2 OK GETQUOTAROOT completed"),
		"{response}"
	);

	let response = text(&session.command_line("a3 GETQUOTA \"\""));
	assert!(response.contains("STORAGE "), "{response}");
	assert!(response.contains("a3 OK GETQUOTA completed"), "{response}");

	// GETQUOTA requires authentication.
	let mut anon = Session::new("mail.example.org", dir.path().to_path_buf(), directory());
	assert!(text(&anon.command_line("b1 GETQUOTA \"\"")).contains("b1 NO"));
}

#[test]
fn append_over_quota_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = Session::new("mail.example.org", dir.path().to_path_buf(), directory())
		.with_quota_limit(100);
	session.command_line(&format!("a1 LOGIN alice {}", fixtures::password()));
	// A 200-byte APPEND exceeds the quota and is refused before the literal.
	let output = session.command_line("a2 APPEND INBOX {200}");
	let response = text(&output);
	assert!(response.contains("a2 NO [OVERQUOTA]"), "{response}");
	assert_eq!(
		output.collect_literal, None,
		"literal must not be collected"
	);
	// A small APPEND within quota still works.
	let output = session.command_line("a3 APPEND INBOX {10}");
	assert_eq!(output.collect_literal, Some(10));
}

#[test]
fn authenticate_oauthbearer_succeeds() {
	use base64::Engine;
	use base64::engine::general_purpose::STANDARD as B64;
	use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
	use ring::rand::SystemRandom;
	use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};

	let rng = SystemRandom::new();
	let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
	let pair =
		EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();
	let public_b64 = B64.encode(pair.public_key().as_ref());
	let verifier = std::sync::Arc::new(
		crate::oauth::OauthVerifier::new("https://idp.example", "mail", "ES256", &public_b64)
			.expect("verifier"),
	);
	let header = B64URL.encode(br#"{"alg":"ES256","typ":"JWT"}"#);
	let payload = B64URL.encode(
		serde_json::to_vec(&serde_json::json!({
			"iss": "https://idp.example",
			"aud": "mail",
			"email": "alice@example.org",
			"email_verified": true,
			"exp": 99_999_999_999u64,
		}))
		.unwrap(),
	);
	let input = format!("{header}.{payload}");
	let sig = pair.sign(&rng, input.as_bytes()).unwrap();
	let token = format!("{input}.{}", B64URL.encode(sig.as_ref()));
	let response = B64.encode(format!(
		"n,a=alice@example.org,\x01auth=Bearer {token}\x01\x01"
	));

	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = Session::new("mail.example.org", dir.path().to_path_buf(), directory())
		.with_oauth(Some(verifier));
	// Capability advertises the OAuth mechanisms when a verifier is configured.
	assert!(
		text(&session.command_line("a0 CAPABILITY")).contains("AUTH=OAUTHBEARER"),
		"capability should advertise OAUTHBEARER"
	);
	let response = text(&session.command_line(&format!("a1 AUTHENTICATE OAUTHBEARER {response}")));
	assert!(
		response.contains("a1 OK AUTHENTICATE completed"),
		"{response}"
	);

	// Without a configured verifier, OAUTHBEARER is refused.
	let dir2 = tempfile::tempdir().expect("tempdir");
	let mut s2 = Session::new("mail.example.org", dir2.path().to_path_buf(), directory());
	let bad = B64.encode("n,a=alice@example.org,\x01auth=Bearer not.a.jwt\x01\x01");
	let r2 = text(&s2.command_line(&format!("a1 AUTHENTICATE OAUTHBEARER {bad}")));
	assert!(r2.contains("a1 NO"), "{r2}");
}

#[test]
fn authenticate_plain_succeeds() {
	use base64::Engine;
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = Session::new("mail.example.org", dir.path().to_path_buf(), directory());
	let response = base64::engine::general_purpose::STANDARD
		.encode(format!("\0alice\0{}", fixtures::password()));
	let output = session.command_line(&format!("a1 AUTHENTICATE PLAIN {response}"));
	assert!(
		text(&output).contains("a1 OK AUTHENTICATE completed"),
		"{}",
		text(&output)
	);
}

#[test]
fn authenticate_login_succeeds() {
	use base64::Engine;
	use base64::engine::general_purpose::STANDARD as B64;
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = Session::new("mail.example.org", dir.path().to_path_buf(), directory());
	// AUTHENTICATE LOGIN: username prompt, password prompt, then success.
	assert!(text(&session.command_line("a1 AUTHENTICATE LOGIN")).starts_with("+ "));
	assert!(text(&session.auth_response(&B64.encode("alice"))).starts_with("+ "));
	let ok = text(&session.auth_response(&B64.encode(fixtures::password())));
	assert!(ok.contains("a1 OK AUTHENTICATE completed"), "{ok}");

	// A wrong password fails.
	let mut session = Session::new("mail.example.org", dir.path().to_path_buf(), directory());
	session.command_line("a2 AUTHENTICATE LOGIN");
	session.auth_response(&B64.encode("alice"));
	let no = text(&session.auth_response(&B64.encode("wrong")));
	assert!(no.contains("a2 NO"), "{no}");
}

#[test]
fn authenticate_scram_sha256_succeeds() {
	let nonce = fixtures::nonce();
	use base64::Engine;
	use base64::engine::general_purpose::STANDARD as B64;
	use ring::{digest, hmac, pbkdf2};
	use std::num::NonZeroU32;

	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = Session::new(
		"mail.example.org",
		dir.path().to_path_buf(),
		scram_directory(),
	)
	.with_scram_nonce(fixtures::nonce());
	let output = session.command_line(&format!(
		"a1 AUTHENTICATE SCRAM-SHA-256 {}",
		B64.encode("n,,n=alice,r=CN")
	));
	assert!(output.collect_auth, "should request a continuation");

	let salt = fixtures::salt();
	let server_first = format!("r=CN{nonce},s={},i=4096", B64.encode(salt));
	let without_proof = format!("c=biws,r=CN{nonce}");
	let auth_message = format!("n=alice,r=CN,{server_first},{without_proof}");
	let mut salted = [0u8; 32];
	pbkdf2::derive(
		pbkdf2::PBKDF2_HMAC_SHA256,
		NonZeroU32::new(4096).unwrap(),
		salt,
		fixtures::password().as_bytes(),
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

	let output = session.auth_response(&B64.encode(&client_final));
	let response = text(&output);
	assert!(response.contains("a1 OK"), "{response}");
	assert!(response.contains("[SASL "), "{response}");
}

#[test]
fn unselect_leaves_mailbox() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	session.command_line("a2 SELECT INBOX");
	let response = text(&session.command_line("a3 UNSELECT"));
	assert!(response.contains("a3 OK UNSELECT completed"), "{response}");
	// No mailbox selected afterwards.
	assert!(
		text(&session.command_line("a4 UNSELECT")).contains("a4 BAD"),
		"second UNSELECT should fail"
	);
}

#[test]
fn enable_acknowledges_capabilities() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	let response = text(&session.command_line("a2 ENABLE IMAP4rev2 BOGUS"));
	assert!(response.contains("* ENABLED IMAP4rev2"), "{response}");
	assert!(response.contains("a2 OK ENABLE completed"), "{response}");
	// CONDSTORE and QRESYNC are real capabilities and are echoed; unknown ones
	// (BOGUS) are not.
	let response = text(&session.command_line("a3 ENABLE QRESYNC CONDSTORE BOGUS"));
	assert!(
		response.contains("* ENABLED QRESYNC CONDSTORE"),
		"{response}"
	);
	assert!(!response.contains("BOGUS"), "{response}");
}

#[test]
fn starttls_inside_tls_is_bad() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	let output = session.command_line("a2 STARTTLS");
	assert!(text(&output).contains("a2 BAD"), "{}", text(&output));
	assert!(!output.upgrade_tls);
}

#[test]
fn logout_closes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	let output = session.command_line("a2 LOGOUT");
	assert!(output.close);
	assert!(text(&output).contains("* BYE"));
}

#[test]
fn examine_is_read_only() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	let output = session.command_line("a2 EXAMINE INBOX");
	assert!(text(&output).contains("READ-ONLY"));
}

#[test]
fn unknown_mailbox_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	let output = session.command_line("a2 SELECT Missing");
	assert!(text(&output).contains("a2 NO"));
}
