//! Tests for the ManageSieve session state machine.

use super::*;
use std::path::PathBuf;

struct TestBackend {
	root: PathBuf,
}

impl Backend for TestBackend {
	fn verify(
		&self,
		authcid: &str,
		password: &str,
		_peer_ip: Option<std::net::IpAddr>,
	) -> Option<String> {
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
fn repeated_auth_failures_close_the_connection() {
	let (mut s, _dir) = session(true);
	let bad = || Command::Authenticate {
		mechanism: "PLAIN".to_string(),
		initial: Some({
			use base64::Engine;
			base64::engine::general_purpose::STANDARD.encode("\0alice@example.org\0wrong")
		}),
	};
	// First two failures keep the connection open.
	assert_eq!(
		s.handle(bad()),
		Response::No(Some("Authentication failed.".to_string()))
	);
	assert_eq!(
		s.handle(bad()),
		Response::No(Some("Authentication failed.".to_string()))
	);
	// The third closes it, so an attacker cannot keep guessing on one connection.
	let third = s.handle(bad());
	assert!(matches!(third, Response::Bye(_)), "{third:?}");
	assert!(third.is_final());
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

/// A ManageSieve authentication failure reaches the directory's
/// `authenticate_with_ip` with the peer IP the network layer recorded.
/// The test wires a backend that goes through the live directory (with
/// a [`FakeBanStore`] attached), drives an `AUTHENTICATE PLAIN` with
/// the wrong password, and asserts the fake recorded a failure for
/// `ip:<peer>` and `account:<login>`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn managesieve_failures_now_reach_the_directory() {
	use crate::antispam::bans::BanPolicy;
	use crate::antispam::bans::tests::FakeBanStore;
	use std::collections::HashMap;

	let dir = tempfile::tempdir().expect("tempdir");
	let ban_store = std::sync::Arc::new(FakeBanStore::new(BanPolicy::default()));
	let directory = std::sync::Arc::new(
		crate::smtp::directory::Directory::new(
			["example.org".to_string()],
			[("alice@example.org".to_string(), "alice".to_string())],
		)
		.with_password_hashes(HashMap::from([(
			"alice".to_string(),
			crate::smtp::auth::tests::hash("secret"),
		)]))
		.with_ban_store(ban_store.clone()),
	);
	let accounts_root = dir.path().to_path_buf();
	let backend = DirBackend {
		directory,
		accounts_root,
	};
	let mut session = Session::new(backend, true);
	let peer: std::net::IpAddr = "203.0.113.30".parse().expect("peer");
	session.set_peer_ip(Some(peer));
	let bad = sasl_plain_initial("alice@example.org", "wrong");
	let response = session.handle(Command::Authenticate {
		mechanism: "PLAIN".to_string(),
		initial: Some(bad),
	});
	assert_eq!(
		response,
		Response::No(Some("Authentication failed.".to_string())),
		"ManageSieve failure must reach the directory and return NO"
	);
	assert!(
		ban_store.call_count("record_failure") >= 2,
		"ban store recorded {} failure(s); expected at least two (IP and account)",
		ban_store.call_count("record_failure")
	);
	assert!(
		ban_store.failure_count("ip:203.0.113.30", 0) >= 1,
		"ban store did not record a failure for ip:203.0.113.30"
	);
	assert!(
		ban_store.failure_count("account:alice", 0) >= 1,
		"ban store did not record a failure for account:alice"
	);
}

/// Backend that routes credential verification through the live
/// directory (the production shape), keeping `store` for the in-memory
/// script storage the session needs afterwards.
struct DirBackend {
	directory: std::sync::Arc<crate::smtp::directory::Directory>,
	accounts_root: PathBuf,
}

impl Backend for DirBackend {
	fn verify(
		&self,
		authcid: &str,
		password: &str,
		peer_ip: Option<std::net::IpAddr>,
	) -> Option<String> {
		self.directory.authenticate_with_ip(
			authcid,
			password,
			peer_ip,
			crate::config::Protocol::ManageSieve,
		)
	}
	fn store(&self, account: &str) -> ScriptStore {
		ScriptStore::new(&self.accounts_root, account)
	}
}

/// Encode `\0authcid\0password` for SASL PLAIN initial response.
fn sasl_plain_initial(authcid: &str, password: &str) -> String {
	use base64::Engine;
	base64::engine::general_purpose::STANDARD.encode(format!("\0{authcid}\0{password}"))
}
