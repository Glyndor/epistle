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

fn b64_bytes(bytes: &[u8]) -> String {
	use base64::Engine;
	base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// A 32-byte stand-in for the tls-server-end-point certificate hash.
const CERT_HASH: &[u8] = b"0123456789abcdef0123456789abcdef";

/// A SCRAM session on a TLS link that also offers channel binding (-PLUS).
fn scram_plus_session() -> Session {
	Session::new("mail.example.org")
		.with_directory(scram_directory())
		.with_tls_active()
		.with_channel_binding(CERT_HASH.to_vec())
		.with_scram_nonce("SN")
		.tap_ehlo()
}

trait TapEhlo {
	fn tap_ehlo(self) -> Self;
}
impl TapEhlo for Session {
	fn tap_ehlo(mut self) -> Self {
		self.command_line("EHLO client.example.org");
		self
	}
}

#[test]
fn scram_plus_negotiates_when_bound() {
	let mut session = scram_plus_session();
	let action = session.command_line(&format!(
		"AUTH SCRAM-SHA-256-PLUS {}",
		b64("p=tls-server-end-point,,n=alice,r=CN")
	));
	assert_eq!(
		reply_code(&action),
		334,
		"bound -PLUS client-first is challenged"
	);
}

#[test]
fn scram_plus_unavailable_without_binding() {
	// No channel binding configured → the -PLUS mechanism is not offered.
	let mut session = scram_session(true);
	let action = session.command_line(&format!(
		"AUTH SCRAM-SHA-256-PLUS {}",
		b64("p=tls-server-end-point,,n=alice,r=CN")
	));
	assert_eq!(reply_code(&action), 504);
}

#[test]
fn scram_plus_wrong_binding_is_rejected() {
	let mut session = scram_plus_session();
	assert_eq!(
		reply_code(&session.command_line(&format!(
			"AUTH SCRAM-SHA-256-PLUS {}",
			b64("p=tls-server-end-point,,n=alice,r=CN")
		))),
		334
	);
	// client-final whose c= carries the wrong binding data.
	let wrong = b64_bytes(b"WRONGWRONGWRONGWRONGWRONGWRONG!!");
	let client_final = format!("c={wrong},r=CNSN,p={}", b64_bytes(&[0u8; 32]));
	assert_eq!(reply_code(&session.auth_line(&b64(&client_final))), 535);
}

#[test]
fn scram_plain_rejects_downgrade_when_bound() {
	// On a link that offers -PLUS, plain SCRAM with `y,,` is a downgrade.
	let mut session = scram_plus_session();
	let action = session.command_line(&format!("AUTH SCRAM-SHA-256 {}", b64("y,,n=alice,r=CN")));
	assert_eq!(reply_code(&action), 535);
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
