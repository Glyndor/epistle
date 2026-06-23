//! Tests for the ManageSieve session state machine.

use super::*;
use std::path::PathBuf;

struct TestBackend {
	root: PathBuf,
}

impl Backend for TestBackend {
	fn verify(&self, authcid: &str, password: &str) -> Option<String> {
		(authcid == "alice@example.org" && password == "secret").then(|| "alice".to_string())
	}
	fn store(&self, account: &str) -> ScriptStore {
		ScriptStore::new(&self.root, account)
	}
}

fn session(tls: bool) -> (Session<TestBackend>, tempfile::TempDir) {
	let dir = tempfile::tempdir().expect("tempdir");
	let backend = TestBackend {
		root: dir.path().to_path_buf(),
	};
	(Session::new(backend, tls), dir)
}

/// SASL PLAIN initial response for alice.
fn plain() -> String {
	use base64::Engine;
	base64::engine::general_purpose::STANDARD.encode("\0alice@example.org\0secret")
}

fn login(s: &mut Session<TestBackend>) {
	let response = s.handle(Command::Authenticate {
		mechanism: "PLAIN".to_string(),
		initial: Some(plain()),
	});
	assert_eq!(response, Response::Ok(Some("Authenticated.".to_string())));
}

#[test]
fn greeting_advertises_starttls_before_tls() {
	let (s, _dir) = session(false);
	let bytes = s.greeting().encode();
	let text = String::from_utf8(bytes).expect("utf8");
	assert!(text.contains("\"STARTTLS\""), "{text}");
	assert!(!text.contains("\"SASL\""), "{text}");
	assert!(text.contains("\"IMPLEMENTATION\" \"epistle\""), "{text}");
}

#[test]
fn capability_advertises_sasl_after_tls() {
	let (mut s, _dir) = session(false);
	s.set_tls();
	let text = String::from_utf8(s.handle(Command::Capability).encode()).expect("utf8");
	assert!(text.contains("\"SASL\" \"PLAIN\""), "{text}");
	assert!(!text.contains("\"STARTTLS\""), "{text}");
}

#[test]
fn capability_advertises_implemented_sieve_extensions() {
	let (mut s, _dir) = session(false);
	let text = String::from_utf8(s.handle(Command::Capability).encode()).expect("utf8");
	// Every extension the interpreter honors must be advertised so clients can
	// `require` it.
	for ext in [
		"fileinto",
		"vacation",
		"imap4flags",
		"relational",
		"variables",
		"reject",
		"ereject",
		"copy",
		"body",
		"date",
		"comparator-i;ascii-numeric",
	] {
		assert!(text.contains(ext), "missing {ext} in: {text}");
	}
}

#[test]
fn auth_refused_without_tls() {
	let (mut s, _dir) = session(false);
	let response = s.handle(Command::Authenticate {
		mechanism: "PLAIN".to_string(),
		initial: Some(plain()),
	});
	assert!(matches!(response, Response::NoCode("ENCRYPT-NEEDED", _)));
}

#[test]
fn auth_succeeds_over_tls_and_bad_credentials_fail() {
	let (mut s, _dir) = session(true);
	let bad = s.handle(Command::Authenticate {
		mechanism: "PLAIN".to_string(),
		initial: Some({
			use base64::Engine;
			base64::engine::general_purpose::STANDARD.encode("\0alice@example.org\0wrong")
		}),
	});
	assert_eq!(
		bad,
		Response::No(Some("Authentication failed.".to_string()))
	);
	login(&mut s);
}

#[test]
fn starttls_signals_upgrade_then_refuses_repeat() {
	let (mut s, _dir) = session(false);
	let response = s.handle(Command::StartTls);
	assert!(response.starts_tls());
	s.set_tls();
	assert!(matches!(s.handle(Command::StartTls), Response::No(_)));
}

#[test]
fn script_commands_require_auth() {
	let (mut s, _dir) = session(true);
	assert_eq!(
		s.handle(Command::ListScripts),
		Response::No(Some("Authenticate first.".to_string()))
	);
}

#[test]
fn put_list_get_setactive_delete_flow() {
	let (mut s, _dir) = session(true);
	login(&mut s);
	// PUTSCRIPT a valid script.
	assert_eq!(
		s.handle(Command::PutScript {
			name: "work".to_string(),
			content: "keep;\r\n".to_string(),
		}),
		Response::Ok(None)
	);
	// LISTSCRIPTS shows it, not yet active.
	let listed = String::from_utf8(s.handle(Command::ListScripts).encode()).expect("utf8");
	assert!(listed.contains("\"work\"\r\n"), "{listed}");
	assert!(!listed.contains("ACTIVE"), "{listed}");
	// SETACTIVE then LISTSCRIPTS flags it.
	assert_eq!(
		s.handle(Command::SetActive("work".to_string())),
		Response::Ok(None)
	);
	let listed = String::from_utf8(s.handle(Command::ListScripts).encode()).expect("utf8");
	assert!(listed.contains("\"work\" ACTIVE"), "{listed}");
	// GETSCRIPT returns the body as a literal.
	let got =
		String::from_utf8(s.handle(Command::GetScript("work".to_string())).encode()).expect("utf8");
	assert!(got.starts_with("{7}\r\nkeep;\r\n"), "{got}");
	// Deleting the active script is refused.
	assert!(matches!(
		s.handle(Command::DeleteScript("work".to_string())),
		Response::NoCode("ACTIVE", _)
	));
}

#[test]
fn putscript_rejects_invalid_sieve() {
	let (mut s, _dir) = session(true);
	login(&mut s);
	let response = s.handle(Command::PutScript {
		name: "bad".to_string(),
		content: "if if if".to_string(),
	});
	assert!(matches!(response, Response::No(Some(_))));
}

#[test]
fn checkscript_validates_without_storing() {
	let (mut s, _dir) = session(true);
	login(&mut s);
	assert_eq!(
		s.handle(Command::CheckScript {
			content: "keep;\r\n".to_string(),
		}),
		Response::Ok(None)
	);
	assert!(matches!(
		s.handle(Command::CheckScript {
			content: "bogus bogus".to_string(),
		}),
		Response::No(Some(_))
	));
	// Nothing was stored: the list has no script lines, only the final OK.
	let listed = String::from_utf8(s.handle(Command::ListScripts).encode()).expect("utf8");
	assert_eq!(listed, "OK \"Listed.\"\r\n", "{listed}");
}

#[test]
fn getscript_missing_is_nonexistent() {
	let (mut s, _dir) = session(true);
	login(&mut s);
	assert!(matches!(
		s.handle(Command::GetScript("ghost".to_string())),
		Response::NoCode("NONEXISTENT", _)
	));
}

#[test]
fn unauthenticate_returns_to_preauth() {
	let (mut s, _dir) = session(true);
	login(&mut s);
	assert_eq!(s.handle(Command::Unauthenticate), Response::Ok(None));
	assert_eq!(
		s.handle(Command::ListScripts),
		Response::No(Some("Authenticate first.".to_string()))
	);
}

#[test]
fn logout_is_final() {
	let (mut s, _dir) = session(true);
	let response = s.handle(Command::Logout);
	assert!(response.is_final());
}
