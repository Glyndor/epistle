use super::*;

fn reply_code(action: &Action) -> u16 {
	match action {
		Action::Continue(r)
		| Action::CollectData(r)
		| Action::UpgradeTls(r)
		| Action::CollectAuthResponse(r)
		| Action::Close(r) => r.code(),
		Action::Deliver(r, _) => r.code(),
		Action::CollectChunk { .. } => 0,
	}
}

fn reply_text(action: &Action) -> String {
	match action {
		Action::Continue(r)
		| Action::CollectData(r)
		| Action::UpgradeTls(r)
		| Action::CollectAuthResponse(r)
		| Action::Close(r) => r.to_string(),
		Action::Deliver(r, _) => r.to_string(),
		Action::CollectChunk { .. } => String::new(),
	}
}

fn auth_directory() -> Arc<Directory> {
	Arc::new(
		Directory::new(
			["example.org".to_string()],
			[("alice@example.org".to_string(), "alice".to_string())],
		)
		.with_password_hashes([(
			"alice".to_string(),
			crate::smtp::auth::tests::hash("secret"),
		)]),
	)
}

fn plain(authcid: &str, password: &str) -> String {
	use base64::Engine;
	base64::engine::general_purpose::STANDARD.encode(format!("\0{authcid}\0{password}"))
}

fn tls_session() -> Session {
	let mut session = Session::new("mail.example.org")
		.with_directory(auth_directory())
		.with_tls_active();
	session.command_line("EHLO client.example.org");
	session
}

fn authenticated_session() -> Session {
	let mut session = tls_session();
	session.command_line(&format!("AUTH PLAIN {}", plain("alice", "secret")));
	assert_eq!(session.authenticated(), Some("alice"));
	session
}

// Unauthenticated session with no TLS — used for relay/sender tests.
fn greeted_plain() -> Session {
	let mut session = Session::new("mail.example.org").with_directory(auth_directory());
	session.command_line("EHLO client.example.org");
	session
}

#[test]
fn auth_login_authenticates() {
	use base64::Engine;
	use base64::engine::general_purpose::STANDARD as B64;
	let mut session = tls_session();
	// AUTH LOGIN prompts for the username, then the password.
	let action = session.command_line("AUTH LOGIN");
	assert_eq!(reply_code(&action), 334);
	let action = session.auth_line(&B64.encode("alice"));
	assert_eq!(reply_code(&action), 334);
	let action = session.auth_line(&B64.encode("secret"));
	assert_eq!(reply_code(&action), 235);
	assert_eq!(session.authenticated(), Some("alice"));

	// A wrong password fails (no oracle).
	let mut session = tls_session();
	session.command_line("AUTH LOGIN");
	session.auth_line(&B64.encode("alice"));
	let action = session.auth_line(&B64.encode("wrong"));
	assert_eq!(reply_code(&action), 535);
	assert_eq!(session.authenticated(), None);
}

#[test]
fn scram_sha256_authenticates() {
	use crate::smtp::scram::{ScramCredentials, ScramStored};
	use base64::Engine;
	use base64::engine::general_purpose::STANDARD as B64;
	use ring::{digest, hmac, pbkdf2};
	use std::num::NonZeroU32;

	let salt = b"saltsalt";
	let stored = ScramStored::from_credentials(&ScramCredentials::derive("secret", salt, 4096));
	let directory = Arc::new(
		Directory::new(
			["example.org".to_string()],
			[("alice@example.org".to_string(), "alice".to_string())],
		)
		.with_password_hashes([(
			"alice".to_string(),
			crate::smtp::auth::tests::hash("secret"),
		)])
		.with_scram([("alice".to_string(), stored)]),
	);
	let mut session = Session::new("mail.example.org")
		.with_directory(directory)
		.with_tls_active()
		.with_scram_nonce("SN");
	session.command_line("EHLO client.example.org");

	// AUTH SCRAM-SHA-256 with the client-first as the initial response.
	let action = session.command_line(&format!(
		"AUTH SCRAM-SHA-256 {}",
		B64.encode("n,,n=alice,r=CN")
	));
	assert_eq!(reply_code(&action), 334);

	// The server-first is deterministic given the fixed nonce and salt.
	let server_first = format!("r=CNSN,s={},i=4096", B64.encode(salt));
	let without_proof = "c=biws,r=CNSN";
	let auth_message = format!("n=alice,r=CN,{server_first},{without_proof}");

	// Client computes its proof from the password.
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

	let action = session.auth_line(&B64.encode(&client_final));
	assert_eq!(reply_code(&action), 235);
	assert_eq!(session.authenticated(), Some("alice"));
}

#[test]
fn scram_sha256_wrong_password_fails() {
	use crate::smtp::scram::{ScramCredentials, ScramStored};
	use base64::Engine;
	use base64::engine::general_purpose::STANDARD as B64;

	let stored =
		ScramStored::from_credentials(&ScramCredentials::derive("secret", b"saltsalt", 4096));
	let directory = Arc::new(
		Directory::new(
			["example.org".to_string()],
			[("alice@example.org".to_string(), "alice".to_string())],
		)
		.with_password_hashes([(
			"alice".to_string(),
			crate::smtp::auth::tests::hash("secret"),
		)])
		.with_scram([("alice".to_string(), stored)]),
	);
	let mut session = Session::new("mail.example.org")
		.with_directory(directory)
		.with_tls_active()
		.with_scram_nonce("SN");
	session.command_line("EHLO client.example.org");
	session.command_line(&format!(
		"AUTH SCRAM-SHA-256 {}",
		B64.encode("n,,n=alice,r=CN")
	));
	// A bogus (well-formed but wrong) proof of 32 zero bytes fails.
	let bad = format!("c=biws,r=CNSN,p={}", B64.encode([0u8; 32]));
	let action = session.auth_line(&B64.encode(&bad));
	assert_eq!(reply_code(&action), 535);
	assert_eq!(session.authenticated(), None);
}

#[test]
fn auth_rejected_outside_tls() {
	let mut session = greeted_plain();
	let action = session.command_line(&format!("AUTH PLAIN {}", plain("alice", "secret")));
	assert_eq!(reply_code(&action), 538);
	assert_eq!(session.authenticated(), None);
}

#[test]
fn ehlo_advertises_auth_only_inside_tls() {
	let mut plain_session = greeted_plain();
	let Action::Continue(reply) = plain_session.command_line("EHLO c.example.org") else {
		panic!("expected continue");
	};
	assert!(!reply.to_string().contains("AUTH "));

	let mut tls = tls_session();
	let Action::Continue(reply) = tls.command_line("EHLO c.example.org") else {
		panic!("expected continue");
	};
	assert!(
		reply.to_string().contains("AUTH SCRAM-SHA-256 PLAIN"),
		"{reply}"
	);
}

#[test]
fn ehlo_advertises_requiretls_only_inside_tls() {
	let mut plain_session = greeted_plain();
	let Action::Continue(reply) = plain_session.command_line("EHLO c.example.org") else {
		panic!("expected continue");
	};
	assert!(!reply.to_string().contains("REQUIRETLS"), "{reply}");

	let mut tls = tls_session();
	let Action::Continue(reply) = tls.command_line("EHLO c.example.org") else {
		panic!("expected continue");
	};
	assert!(reply.to_string().contains("REQUIRETLS"), "{reply}");
}

#[test]
fn requiretls_rejected_without_tls() {
	let mut session = greeted_plain();
	let action = session.command_line("MAIL FROM:<eve@sender.example> REQUIRETLS");
	assert_eq!(reply_code(&action), 530);
}

#[test]
fn requiretls_accepted_inside_tls() {
	let mut session = tls_session();
	let action = session.command_line("MAIL FROM:<eve@sender.example> REQUIRETLS");
	assert_eq!(reply_code(&action), 250);
}

#[test]
fn requiretls_flows_to_accepted_message() {
	let mut session = tls_session();
	session.command_line("MAIL FROM:<eve@sender.example> REQUIRETLS");
	session.command_line("RCPT TO:<alice@example.org>");
	session.command_line("DATA");
	session.data_line(b"Subject: hi");
	session.data_line(b"");
	session.data_line(b"body");
	let Some(Action::Deliver(_, message)) = session.data_line(b".") else {
		panic!("expected delivery");
	};
	assert!(
		message.require_tls,
		"REQUIRETLS must reach the accepted message"
	);
}

#[test]
fn auth_with_initial_response_succeeds() {
	let mut session = tls_session();
	let action = session.command_line(&format!("AUTH PLAIN {}", plain("alice", "secret")));
	assert_eq!(reply_code(&action), 235);
	assert_eq!(session.authenticated(), Some("alice"));
}

#[test]
fn auth_by_address_succeeds() {
	let mut session = tls_session();
	let action = session.command_line(&format!(
		"AUTH PLAIN {}",
		plain("alice@example.org", "secret")
	));
	assert_eq!(reply_code(&action), 235);
}

#[test]
fn auth_challenge_flow_succeeds() {
	let mut session = tls_session();
	let action = session.command_line("AUTH PLAIN");
	assert!(matches!(action, Action::CollectAuthResponse(_)));
	assert_eq!(reply_code(&action), 334);
	let action = session.auth_line(&plain("alice", "secret"));
	assert_eq!(reply_code(&action), 235);
}

#[test]
fn auth_challenge_can_be_cancelled() {
	let mut session = tls_session();
	session.command_line("AUTH PLAIN");
	let action = session.auth_line("*");
	assert_eq!(reply_code(&action), 501);
	assert_eq!(session.authenticated(), None);
}

#[test]
fn wrong_password_gets_535_without_detail() {
	let mut session = tls_session();
	let action = session.command_line(&format!("AUTH PLAIN {}", plain("alice", "wrong")));
	assert_eq!(reply_code(&action), 535);
	assert_eq!(session.authenticated(), None);
}

#[test]
fn unknown_user_gets_same_reply_as_wrong_password() {
	let mut session = tls_session();
	let action = session.command_line(&format!("AUTH PLAIN {}", plain("mallory", "secret")));
	assert_eq!(reply_code(&action), 535);
}

#[test]
fn third_failure_closes_connection() {
	let mut session = tls_session();
	for _ in 0..2 {
		let action = session.command_line(&format!("AUTH PLAIN {}", plain("alice", "wrong")));
		assert!(matches!(action, Action::Continue(_)));
	}
	let action = session.command_line(&format!("AUTH PLAIN {}", plain("alice", "wrong")));
	assert!(matches!(action, Action::Close(_)));
}

#[test]
fn auth_after_success_is_bad_sequence() {
	let mut session = tls_session();
	session.command_line(&format!("AUTH PLAIN {}", plain("alice", "secret")));
	let action = session.command_line(&format!("AUTH PLAIN {}", plain("alice", "secret")));
	assert_eq!(reply_code(&action), 503);
}

#[test]
fn unsupported_mechanism_gets_504() {
	let mut session = tls_session();
	assert_eq!(reply_code(&session.command_line("AUTH CRAM-MD5")), 504);
}

#[test]
fn auth_inside_transaction_is_bad_sequence() {
	let mut session = tls_session();
	session.command_line("MAIL FROM:<alice@example.org>");
	let action = session.command_line(&format!("AUTH PLAIN {}", plain("alice", "secret")));
	assert_eq!(reply_code(&action), 503);
}

#[test]
fn authenticated_user_may_relay_to_foreign_domains() {
	let mut session = authenticated_session();
	session.command_line("MAIL FROM:<alice@example.org>");
	let action = session.command_line("RCPT TO:<bob@elsewhere.example>");
	assert_eq!(reply_code(&action), 250);
}

#[test]
fn unauthenticated_relay_stays_denied() {
	let mut session = tls_session();
	session.command_line("MAIL FROM:<someone@elsewhere.example>");
	let action = session.command_line("RCPT TO:<bob@elsewhere.example>");
	assert_eq!(reply_code(&action), 550);
}

#[test]
fn authenticated_sender_must_own_the_address() {
	let mut session = authenticated_session();
	let action = session.command_line("MAIL FROM:<other@elsewhere.example>");
	assert_eq!(reply_code(&action), 553);
}

#[test]
fn authenticated_sender_cannot_use_null_path() {
	let mut session = authenticated_session();
	let action = session.command_line("MAIL FROM:<>");
	assert_eq!(reply_code(&action), 553);
}

#[test]
fn authenticated_relay_still_rejects_unknown_local_users() {
	let mut session = authenticated_session();
	session.command_line("MAIL FROM:<alice@example.org>");
	let action = session.command_line("RCPT TO:<stranger@example.org>");
	assert_eq!(reply_code(&action), 550);
}

// TLS / STARTTLS tests

#[test]
fn starttls_without_tls_configured_is_unavailable() {
	let mut session = greeted_plain();
	assert_eq!(reply_code(&session.command_line("STARTTLS")), 454);
}

#[test]
fn ehlo_advertises_starttls_when_available() {
	let mut session = Session::new("mail.example.org").with_tls_available();
	let Action::Continue(reply) = session.command_line("EHLO client.example.org") else {
		panic!("expected continue");
	};
	assert!(reply.to_string().contains("250 STARTTLS\r\n"));
}

#[test]
fn ehlo_advertises_dsn() {
	let mut session = Session::new("mail.example.org");
	let Action::Continue(reply) = session.command_line("EHLO client.example.org") else {
		panic!("expected continue");
	};
	assert!(reply.to_string().contains("250-DSN\r\n"));
}

#[test]
fn ehlo_does_not_advertise_starttls_when_unavailable() {
	let mut session = greeted_plain();
	let Action::Continue(reply) = session.command_line("EHLO client.example.org") else {
		panic!("expected continue");
	};
	assert!(!reply.to_string().contains("STARTTLS"));
}

#[test]
fn starttls_upgrades_after_greeting() {
	let mut session = Session::new("mail.example.org").with_tls_available();
	session.command_line("EHLO client.example.org");
	let action = session.command_line("STARTTLS");
	assert!(matches!(action, Action::UpgradeTls(_)));
	assert_eq!(reply_code(&action), 220);
}

#[test]
fn starttls_before_greeting_is_bad_sequence() {
	let mut session = Session::new("mail.example.org").with_tls_available();
	assert_eq!(reply_code(&session.command_line("STARTTLS")), 503);
}

#[test]
fn starttls_inside_transaction_is_bad_sequence() {
	let mut session = Session::new("mail.example.org").with_tls_available();
	session.command_line("EHLO client.example.org");
	session.command_line("MAIL FROM:<a@example.org>");
	assert_eq!(reply_code(&session.command_line("STARTTLS")), 503);
}

#[test]
fn tls_started_resets_session() {
	let mut session = Session::new("mail.example.org").with_tls_available();
	session.command_line("EHLO client.example.org");
	session.tls_started();
	assert_eq!(
		reply_code(&session.command_line("MAIL FROM:<a@example.org>")),
		503
	);
	let Action::Continue(reply) = session.command_line("EHLO client.example.org") else {
		panic!("expected continue");
	};
	assert!(!reply.to_string().contains("STARTTLS"));
	assert_eq!(reply_code(&session.command_line("STARTTLS")), 454);
}

#[test]
fn auth_rejects_malformed_base64() {
	use base64::Engine;
	use base64::engine::general_purpose::STANDARD as B64;

	// PLAIN with an undecodable initial response.
	let mut session = tls_session();
	assert_eq!(
		reply_code(&session.command_line("AUTH PLAIN !!!notb64")),
		535
	);

	// LOGIN with an undecodable username.
	let mut session = tls_session();
	session.command_line("AUTH LOGIN");
	assert_eq!(reply_code(&session.auth_line("!!!notb64")), 535);

	// LOGIN with a valid username but an undecodable password.
	let mut session = tls_session();
	session.command_line("AUTH LOGIN");
	session.auth_line(&B64.encode("alice"));
	assert_eq!(reply_code(&session.auth_line("!!!notb64")), 535);
}

#[test]
fn submission_rate_limit_defers_over_the_limit() {
	let limiter = std::sync::Arc::new(crate::smtp::ratelimit::SendLimiter::new(1, 60));
	let mut session = Session::new("mail.example.org")
		.with_directory(auth_directory())
		.with_tls_active()
		.with_send_limiter(limiter);
	session.command_line("EHLO client.example.org");
	session.command_line(&format!("AUTH PLAIN {}", plain("alice", "secret")));
	assert_eq!(session.authenticated(), Some("alice"));

	// First authenticated submission is within the limit.
	let first = session.command_line("MAIL FROM:<alice@example.org>");
	assert_eq!(reply_code(&first), 250);
	session.command_line("RSET");

	// The second within the window exceeds the per-account limit -> 4xx defer.
	let second = session.command_line("MAIL FROM:<alice@example.org>");
	assert_eq!(reply_code(&second), 450);
}

#[test]
fn external_authenticates_with_verified_client_cert() {
	let mut session = Session::new("mail.example.org")
		.with_directory(auth_directory())
		.with_tls_active();
	// The TLS layer recorded a verified certificate identity for this account.
	session.set_client_identity(Some("alice@example.org".to_string()));
	let ehlo = session.command_line("EHLO client.example.org");
	assert!(
		reply_text(&ehlo).contains("EXTERNAL"),
		"EXTERNAL advertised once a client cert is present: {}",
		reply_text(&ehlo)
	);
	// Empty initial response (`=`) means "use the certificate identity".
	let action = session.command_line("AUTH EXTERNAL =");
	assert_eq!(reply_code(&action), 235);
	assert_eq!(session.authenticated(), Some("alice"));
}

#[test]
fn external_is_unavailable_without_a_client_cert() {
	let mut session = Session::new("mail.example.org")
		.with_directory(auth_directory())
		.with_tls_active();
	let ehlo = session.command_line("EHLO client.example.org");
	assert!(
		!reply_text(&ehlo).contains("EXTERNAL"),
		"EXTERNAL not advertised without a client cert"
	);
	// And attempting it is rejected (not advertised).
	let action = session.command_line("AUTH EXTERNAL =");
	assert_eq!(reply_code(&action), 504);
	assert_eq!(session.authenticated(), None);
}

#[test]
fn external_rejects_mismatched_authzid() {
	let mut session = Session::new("mail.example.org")
		.with_directory(auth_directory())
		.with_tls_active();
	session.set_client_identity(Some("alice@example.org".to_string()));
	session.command_line("EHLO client.example.org");
	// Requesting to act as someone other than the certificate identity fails.
	use base64::Engine;
	let authzid = base64::engine::general_purpose::STANDARD.encode("bob@example.org");
	let action = session.command_line(&format!("AUTH EXTERNAL {authzid}"));
	assert_eq!(reply_code(&action), 535);
	assert_eq!(session.authenticated(), None);
}
