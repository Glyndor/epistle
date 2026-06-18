use super::*;

fn reply_code(action: &Action) -> u16 {
	match action {
		Action::Continue(r)
		| Action::CollectData(r)
		| Action::UpgradeTls(r)
		| Action::CollectAuthResponse(r)
		| Action::Close(r) => r.code(),
		Action::Deliver(r, _) => r.code(),
	}
}

fn scram_directory() -> Arc<Directory> {
	use crate::smtp::scram::{ScramCredentials, ScramStored};
	let stored =
		ScramStored::from_credentials(&ScramCredentials::derive("secret", b"saltsalt", 4096));
	Arc::new(
		Directory::new(
			["example.org".to_string()],
			[("alice@example.org".to_string(), "alice".to_string())],
		)
		.with_password_hashes([(
			"alice".to_string(),
			crate::smtp::auth::tests::hash("secret"),
		)])
		.with_scram([("alice".to_string(), stored)]),
	)
}

fn scram_session(inject_nonce: bool) -> Session {
	let mut session = Session::new("mail.example.org")
		.with_directory(scram_directory())
		.with_tls_active();
	if inject_nonce {
		session = session.with_scram_nonce("SN");
	}
	session.command_line("EHLO client.example.org");
	session
}

fn b64(s: &str) -> String {
	use base64::Engine;
	base64::engine::general_purpose::STANDARD.encode(s)
}

#[test]
fn scram_without_initial_prompts_for_client_first() {
	let mut session = scram_session(true);
	// No initial response → empty 334 challenge, then the client-first lands.
	assert_eq!(reply_code(&session.command_line("AUTH SCRAM-SHA-256")), 334);
	assert_eq!(reply_code(&session.auth_line(&b64("n,,n=alice,r=CN"))), 334);
}

#[test]
fn scram_client_first_without_injected_nonce_challenges() {
	// No injected nonce: exercises the random server-nonce path.
	let mut session = scram_session(false);
	let action = session.command_line(&format!("AUTH SCRAM-SHA-256 {}", b64("n,,n=alice,r=CN")));
	assert_eq!(reply_code(&action), 334);
}

#[test]
fn scram_malformed_client_first_is_rejected() {
	// Invalid base64.
	let mut session = scram_session(true);
	assert_eq!(
		reply_code(&session.command_line("AUTH SCRAM-SHA-256 !!!not-base64")),
		535
	);
	// Valid base64 but no username token.
	let mut session = scram_session(true);
	assert_eq!(
		reply_code(&session.command_line(&format!("AUTH SCRAM-SHA-256 {}", b64("n,,x=y")))),
		535
	);
	// Unknown user (no oracle: same 535 as a bad password).
	let mut session = scram_session(true);
	assert_eq!(
		reply_code(
			&session.command_line(&format!("AUTH SCRAM-SHA-256 {}", b64("n,,n=ghost,r=CN")))
		),
		535
	);
}

#[test]
fn scram_repeated_failures_close_the_connection() {
	let mut session = scram_session(true);
	session.command_line("AUTH SCRAM-SHA-256 !!!");
	session.command_line("AUTH SCRAM-SHA-256 !!!");
	let action = session.command_line("AUTH SCRAM-SHA-256 !!!");
	assert!(
		matches!(action, Action::Close(_)),
		"third failure must close"
	);
}
