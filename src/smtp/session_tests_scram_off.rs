//! Behaviour with `[auth] scram = false`.
//!
//! Split into a sibling so `session_tests_auth.rs` and `session_tests.rs`
//! stay under the per-file code-line budget. Every test here exercises
//! the disable path and asserts the exact wire output (capability line
//! and refusal line) plus the on-disk account state, so a future change
//! cannot silently re-enable SCRAM without the assertion firing.

use super::*;
use crate::smtp::auth::tests::{fixture_password, hash as hash_password};

/// Local copy of `session_tests_auth::tls_session` so the toggle tests do not
/// depend on a sibling module's pub(super) items.
fn tls_session() -> super::Session {
	let directory = super::super::directory::Directory::new(
		["example.org".to_string()],
		[("alice@example.org".to_string(), "alice".to_string())],
	)
	.with_password_hashes([("alice".to_string(), hash_password(fixture_password()))]);
	let mut session = super::Session::new("mail.example.org")
		.with_directory(std::sync::Arc::new(directory))
		.with_tls_active();
	session.command_line("EHLO client.example.org");
	session
}

/// Drive an IMAP session's `CAPABILITY` so the test gets the same string a
/// real client would see. `capabilities()` on the IMAP session is private to
/// `auth.rs`, so the toggle test routes the request through `command_line`
/// the way the network layer does and reads the bytes.
fn imap_capability_text(session: &mut crate::imap::session::Session) -> String {
	let action = session.command_line("A1 CAPABILITY");
	String::from_utf8_lossy(&action.bytes).into_owned()
}

#[test]
fn smtp_ehlo_drops_scram_mechanisms_when_scram_disabled() {
	let mut session = tls_session().with_scram_enabled(false);
	let Action::Continue(reply) = session.command_line("EHLO c.example.org") else {
		panic!("expected continue");
	};
	let text = reply.to_string();
	assert!(
		!text.contains("SCRAM-SHA-256"),
		"EHLO inside TLS must not advertise SCRAM-SHA-256 when scram=false, got {text}"
	);
	// PLANE and LOGIN stay in: the password still authenticates.
	assert!(
		text.contains("PLAIN"),
		"PLAIN must still be advertised when scram=false, got {text}"
	);
	assert!(
		text.contains("LOGIN"),
		"LOGIN must still be advertised when scram=false, got {text}"
	);
}

#[test]
fn smtp_auth_scram_is_refused_like_unknown_mechanism() {
	use base64::Engine;
	use base64::engine::general_purpose::STANDARD as B64;
	let mut session = tls_session().with_scram_enabled(false);
	let client_first = B64.encode("n,,n=alice,r=CN");
	let action = session.command_line(&format!("AUTH SCRAM-SHA-256 {client_first}"));
	let Action::Continue(reply) = action else {
		panic!("expected continue");
	};
	assert_eq!(
		reply.code(),
		504,
		"AUTH SCRAM-SHA-256 with scram=false is a 504"
	);
	assert!(
		reply.to_string().contains("5.5.4"),
		"reply must carry the same 5.5.4 reason as an unknown mechanism"
	);
}

#[test]
fn smtp_auth_plus_is_refused_when_scram_disabled() {
	let mut session = tls_session().with_scram_enabled(false);
	let action = session.command_line("AUTH SCRAM-SHA-256-PLUS");
	let Action::Continue(reply) = action else {
		panic!("expected continue");
	};
	assert_eq!(
		reply.code(),
		504,
		"AUTH SCRAM-SHA-256-PLUS with scram=false is a 504"
	);
}

#[test]
fn imap_capability_drops_scram_mechanisms_when_scram_disabled() {
	let directory = std::sync::Arc::new(crate::smtp::directory::Directory::new(
		["example.org".to_string()],
		[("alice@example.org".to_string(), "alice".to_string())],
	));
	let mut session = crate::imap::session::Session::new(
		"imap.example.org",
		std::path::PathBuf::from("/tmp"),
		directory,
	)
	.with_scram_enabled(false);
	let text = imap_capability_text(&mut session);
	assert!(
		!text.contains("AUTH=SCRAM-SHA-256"),
		"CAPABILITY must not advertise AUTH=SCRAM-SHA-256 when scram=false, got {text}"
	);
	// PLAIN stays.
	assert!(
		text.contains("AUTH=PLAIN"),
		"PLAIN must remain in CAPABILITY AUTH= when scram=false, got {text}"
	);
}

#[test]
fn imap_authenticate_scram_is_refused_when_scram_disabled() {
	use base64::Engine;
	let directory = std::sync::Arc::new(crate::smtp::directory::Directory::new(
		["example.org".to_string()],
		[("alice@example.org".to_string(), "alice".to_string())],
	));
	let mut session = crate::imap::session::Session::new(
		"imap.example.org",
		std::path::PathBuf::from("/tmp"),
		directory,
	)
	.with_scram_enabled(false);
	let client_first = base64::engine::general_purpose::STANDARD.encode("n,,n=alice,r=CN");
	let action = session.command_line(&format!("A1 AUTHENTICATE SCRAM-SHA-256 {client_first}"));
	let out = String::from_utf8_lossy(&action.bytes).into_owned();
	assert!(
		out.starts_with("A1 NO "),
		"AUTHENTICATE SCRAM-SHA-256 with scram=false must answer NO, got {out}"
	);
	assert!(
		out.contains("unsupported"),
		"the NO response must carry the same 'unsupported SASL mechanism' reason, got {out}"
	);
}

#[test]
fn directory_with_password_omits_scram_when_disabled() {
	// The AccountStore flag is the source of truth for the wire / on-disk
	// outcome. `DynamicAccount::with_password` carries the flag and writes
	// `scram = None` when it is `false`.
	let password = fixture_password();
	let account = crate::directory_store::DynamicAccount::with_password(
		"alice".to_string(),
		vec!["alice@example.org".to_string()],
		password,
		false,
	)
	.expect("hashed account");
	assert!(
		account.scram.is_none(),
		"scram=false must omit the SCRAM row, got {:?}",
		account.scram
	);
	// Sanity: the password hash is still there, the toggle only affects SCRAM.
	assert!(!account.password_hash.is_empty());
}

#[test]
fn directory_with_password_writes_scram_when_enabled() {
	let password = fixture_password();
	let account = crate::directory_store::DynamicAccount::with_password(
		"alice".to_string(),
		vec!["alice@example.org".to_string()],
		password,
		true,
	)
	.expect("hashed account");
	let scram = account.scram.expect("scram present");
	assert_eq!(scram.iterations, crate::smtp::scram::SCRAM_ITERATIONS);
}

#[test]
fn password_change_drops_an_existing_verifier_when_scram_disabled() {
	// The full path: a dynamic account starts life with a verifier (scram on),
	// the operator flips `[auth] scram = false`, then `set_password_hash`
	// writes `scram = None` because the store's flag is off. A regression
	// that only checked the create path would let an old verifier linger.
	let password = fixture_password();
	let account_with_scram = crate::directory_store::DynamicAccount::with_password(
		"alice".to_string(),
		vec!["alice@example.org".to_string()],
		password,
		true,
	)
	.expect("hashed account");
	assert!(account_with_scram.scram.is_some());

	let dir = tempfile::tempdir().expect("tempdir");
	let store = crate::directory_store::AccountStore::open(
		dir.path(),
		vec!["example.org".to_string()],
		std::collections::HashMap::new(),
		Vec::new(),
	)
	.expect("store open");
	store.add(account_with_scram).expect("add");

	// The live store is built with scram=false to simulate the operator's
	// flag flip after the fact. The same code path is what serve.rs would
	// execute on the next start.
	let store = store.with_scram_enabled(false);
	let upgrader: std::sync::Arc<dyn crate::directory_store::ScramUpgrader> =
		std::sync::Arc::new(crate::directory_store::NoopScramUpgrader);
	let store = store.with_scram_upgrader(upgrader);

	let hash = crate::smtp::auth::hash_password(password).expect("hash");
	store
		.set_password_hash("alice", hash, None)
		.expect("password set with scram disabled");

	let after = store.dynamic("alice").expect("account still present").scram;
	assert!(
		after.is_none(),
		"scram=false must drop the verifier on the next password change, got {after:?}"
	);
}

#[test]
fn managesieve_advertises_plain_only_regardless_of_scram_flag() {
	// ManageSieve never advertised SCRAM: its `Sieve` record carries only
	// PLAIN, and the existing code in `src/managesieve/session.rs::capabilities`
	// only ever pushes a `SASL "PLAIN"` line under STARTTLS, never a SCRAM
	// one. The grep-style static check pins that against future drift that
	// would quietly couple the flag to this listener.
	let src = std::fs::read_to_string(
		std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/managesieve/session.rs"),
	)
	.expect("read session.rs");
	assert!(
		!src.contains("SCRAM"),
		"ManageSieve's session.rs must not mention SCRAM; the toggle does not affect it"
	);
	assert!(
		src.contains("\"PLAIN\""),
		"ManageSieve must still advertise PLAIN as the only SASL mechanism"
	);
}

#[test]
fn unknown_auth_key_in_section_fails_validation() {
	// `deny_unknown_fields` on `[auth]` means a typo is rejected at load.
	use crate::config::Auth;
	let parsed: Result<Auth, _> = toml::from_str("scram = true\nscram_extra = 1\n");
	assert!(parsed.is_err(), "unknown key in [auth] must be rejected");
}

#[test]
fn auth_section_default_is_scram_true() {
	// An absent `[auth]` section keeps the historical default. A regression
	// that dropped the `#[serde(default)]` on the field would make every
	// existing config fail to parse.
	use crate::config::Auth;
	let parsed: Auth = toml::from_str("").expect("parse empty");
	assert!(parsed.scram);
}

/// The SMTP EHLO capability line for AUTH, exactly.
fn smtp_auth_line(session: &mut super::Session) -> String {
	let Action::Continue(reply) = session.command_line("EHLO c.example.org") else {
		panic!("expected continue");
	};
	reply
		.to_string()
		.lines()
		.find(|line| line.contains("AUTH "))
		.map(str::to_string)
		.unwrap_or_default()
}

#[test]
fn smtp_ehlo_auth_line_is_exactly_plain_login_when_scram_disabled() {
	let mut session = tls_session().with_scram_enabled(false);
	assert_eq!(smtp_auth_line(&mut session), "250-AUTH PLAIN LOGIN");
	let mut enabled = tls_session();
	assert_eq!(
		smtp_auth_line(&mut enabled),
		"250-AUTH SCRAM-SHA-256 PLAIN LOGIN",
		"control: the same listener with SCRAM on"
	);
}

#[test]
fn smtp_scram_refusal_is_the_unknown_mechanism_reply() {
	let reply_to = |line: &str| {
		let mut session = tls_session().with_scram_enabled(false);
		let Action::Continue(reply) = session.command_line(line) else {
			panic!("expected continue");
		};
		reply.to_string()
	};
	let unknown = reply_to("AUTH DIGEST-MD5 bixuPWFsaWNlLHI9Q04=");
	assert_eq!(
		reply_to("AUTH SCRAM-SHA-256 bixuPWFsaWNlLHI9Q04="),
		unknown,
		"SCRAM-SHA-256 must be refused byte for byte like an unknown mechanism"
	);
	assert_eq!(
		reply_to("AUTH SCRAM-SHA-256-PLUS"),
		reply_to("AUTH DIGEST-MD5")
	);
}

fn imap_session_scram_off() -> crate::imap::session::Session {
	crate::imap::session::Session::new(
		"imap.example.org",
		std::path::PathBuf::from("/tmp"),
		std::sync::Arc::new(crate::smtp::directory::Directory::new(
			["example.org".to_string()],
			[("alice@example.org".to_string(), "alice".to_string())],
		)),
	)
	.with_scram_enabled(false)
}

#[test]
fn imap_capability_auth_list_is_exactly_plain_login_when_scram_disabled() {
	let text = imap_capability_text(&mut imap_session_scram_off());
	let auth: Vec<&str> = text
		.split_whitespace()
		.filter(|word| word.starts_with("AUTH="))
		.collect();
	assert_eq!(auth, ["AUTH=PLAIN", "AUTH=LOGIN"], "capability: {text}");
}

#[test]
fn imap_scram_refusal_is_the_unknown_mechanism_reply() {
	let reply_to = |line: &str| {
		let action = imap_session_scram_off().command_line(line);
		String::from_utf8_lossy(&action.bytes).into_owned()
	};
	assert_eq!(
		reply_to("A1 AUTHENTICATE SCRAM-SHA-256 bixuPWFsaWNlLHI9Q04="),
		reply_to("A1 AUTHENTICATE DIGEST-MD5 bixuPWFsaWNlLHI9Q04="),
		"SCRAM-SHA-256 must be refused byte for byte like an unknown mechanism"
	);
	assert_eq!(
		reply_to("A1 AUTHENTICATE SCRAM-SHA-256-PLUS"),
		reply_to("A1 AUTHENTICATE DIGEST-MD5")
	);
}
