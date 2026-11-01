//! Every IMAP login path applies the same account rules: a disabled account,
//! an account with a second factor and an address in a switched-off domain
//! are refused by LOGIN, AUTHENTICATE PLAIN and LOGIN, SCRAM, OAUTHBEARER and
//! EXTERNAL alike.

use super::*;
use crate::smtp::directory::gate_fixture::*;
use crate::test_fixtures as fixtures;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

fn session(dir: &std::path::Path, directory: Arc<Directory>) -> Session {
	Session::new("mail.example.org", dir.to_path_buf(), directory)
		.with_scram_nonce(fixtures::nonce())
}

fn is_ok(output: &Output) -> bool {
	text(output).contains(" OK ")
}

fn login(session: &mut Session, user: &str, password: &str) -> bool {
	is_ok(&session.command_line(&format!("a LOGIN {user} {password}")))
}

fn plain(session: &mut Session, user: &str, password: &str) -> bool {
	let response = B64.encode(format!("\0{user}\0{password}"));
	is_ok(&session.command_line(&format!("a AUTHENTICATE PLAIN {response}")))
}

fn auth_login(session: &mut Session, user: &str, password: &str) -> bool {
	session.command_line("a AUTHENTICATE LOGIN");
	session.auth_response(&B64.encode(user));
	is_ok(&session.auth_response(&B64.encode(password)))
}

/// Run SCRAM-SHA-256 for `user`; whether the exchange ended in `OK`.
fn scram(session: &mut Session, user: &str, password: &str) -> bool {
	let bare = format!("n={user},r=CN");
	let first = session.command_line(&format!(
		"a AUTHENTICATE SCRAM-SHA-256 {}",
		B64.encode(format!("n,,{bare}"))
	));
	let first = text(&first);
	let Some(challenge) = first.strip_prefix("+ ") else {
		return false;
	};
	let server_first = String::from_utf8(B64.decode(challenge.trim()).expect("base64 challenge"))
		.expect("utf8 challenge");
	let client_final = scram_client_final(&bare, &server_first, password);
	is_ok(&session.auth_response(&B64.encode(client_final)))
}

#[test]
fn scram_admits_an_open_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = session(dir.path(), gate_directory_arc());
	assert!(scram(&mut session, OPEN, fixtures::password()));
	assert_eq!(session.account(), Some(OPEN));
}

#[test]
fn scram_refuses_a_disabled_account_that_proves_the_password() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = session(dir.path(), gate_directory_arc());
	assert!(
		!scram(&mut session, DISABLED, fixtures::password()),
		"a disabled account must not finish SCRAM"
	);
	assert_eq!(session.account(), None);
}

#[test]
fn scram_refuses_an_account_with_a_second_factor() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = session(dir.path(), gate_directory_arc());
	assert!(
		!scram(&mut session, TWO_FACTOR, fixtures::password()),
		"SCRAM cannot carry the TOTP code"
	);
	assert_eq!(session.account(), None);
}

#[test]
fn scram_refuses_an_address_in_a_switched_off_domain() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = session(dir.path(), gate_directory_arc());
	let user = format!("{OFF_DOMAIN_ACCOUNT}@{OFF_DOMAIN}");
	assert!(!scram(&mut session, &user, fixtures::password()));
	assert_eq!(session.account(), None);
}

#[test]
fn the_account_name_still_signs_in_when_its_domain_is_switched_off() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = session(dir.path(), gate_directory_arc());
	assert!(scram(
		&mut session,
		OFF_DOMAIN_ACCOUNT,
		fixtures::password()
	));
}

#[test]
fn password_commands_refuse_the_same_accounts() {
	let password = fixtures::password();
	let off_address = format!("{OFF_DOMAIN_ACCOUNT}@{OFF_DOMAIN}");
	for user in [DISABLED, TWO_FACTOR, off_address.as_str()] {
		let dir = tempfile::tempdir().expect("tempdir");
		let mut by_login = session(dir.path(), gate_directory_arc());
		assert!(!login(&mut by_login, user, password), "LOGIN {user}");
		assert_eq!(by_login.account(), None);
		let mut by_plain = session(dir.path(), gate_directory_arc());
		assert!(!plain(&mut by_plain, user, password), "PLAIN {user}");
		assert_eq!(by_plain.account(), None);
		let mut by_auth_login = session(dir.path(), gate_directory_arc());
		assert!(
			!auth_login(&mut by_auth_login, user, password),
			"AUTHENTICATE LOGIN {user}"
		);
		assert_eq!(by_auth_login.account(), None);
	}
}

#[test]
fn the_two_factor_code_opens_the_password_commands() {
	let with_code = format!("{}{}", fixtures::password(), current_totp_code());
	let dir = tempfile::tempdir().expect("tempdir");
	assert!(login(
		&mut session(dir.path(), gate_directory_arc()),
		TWO_FACTOR,
		&with_code
	));
	assert!(plain(
		&mut session(dir.path(), gate_directory_arc()),
		TWO_FACTOR,
		&with_code
	));
}

#[test]
fn an_app_password_that_has_expired_or_is_off_its_network_opens_nothing() {
	let (directory, expired, elsewhere) = gate_directory_with_app_passwords();
	let directory = Arc::new(directory);
	for secret in [expired, elsewhere] {
		let dir = tempfile::tempdir().expect("tempdir");
		let mut session = session(dir.path(), directory.clone());
		session.set_peer_ip(Some("203.0.113.9".parse().expect("peer")));
		assert!(!login(&mut session, OPEN, secret));
		assert_eq!(session.account(), None);
	}
}

fn bearer(email: &str, mechanism: &str) -> Output {
	let (verifier, pair, rng) = verifier_and_key();
	let response = bearer_response(&pair, &rng, email);
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = session(dir.path(), gate_directory_arc()).with_oauth(Some(verifier));
	session.command_line(&format!("a AUTHENTICATE {mechanism} {response}"))
}

#[test]
fn a_bearer_token_admits_an_open_account() {
	assert!(is_ok(&bearer("alice@example.org", "OAUTHBEARER")));
}

#[test]
fn a_bearer_token_for_a_disabled_account_is_refused() {
	for mechanism in ["OAUTHBEARER", "XOAUTH2"] {
		assert!(
			!is_ok(&bearer("bob@example.org", mechanism)),
			"{mechanism} must not open a disabled account"
		);
	}
}

fn bearer_with(verifier_attests: bool, email: &str, verified: Option<bool>) -> Output {
	let (verifier, pair, rng) = verifier_and_key_with(verifier_attests);
	let response = bearer_response_verified(&pair, &rng, email, verified);
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = session(dir.path(), gate_directory_arc()).with_oauth(Some(verifier));
	session.command_line(&format!("a AUTHENTICATE OAUTHBEARER {response}"))
}

#[test]
fn a_bearer_token_with_an_unverified_or_unstated_email_opens_nothing() {
	for verified in [Some(false), None] {
		assert!(!is_ok(&bearer_with(false, "alice@example.org", verified)));
	}
}

#[test]
fn a_bearer_token_does_not_skip_the_second_factor_unless_the_provider_enforces_it() {
	assert!(!is_ok(&bearer_with(false, "carol@example.org", Some(true))));
	assert!(is_ok(&bearer_with(true, "carol@example.org", Some(true))));
}

#[test]
fn a_token_of_the_built_in_server_opens_a_second_factor_account() {
	let (verifier, pair, rng) = own_verifier_and_key();
	let response = own_bearer_response(&pair, &rng, TWO_FACTOR);
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = session(dir.path(), gate_directory_arc()).with_oauth(Some(verifier));
	assert!(is_ok(&session.command_line(&format!(
		"a AUTHENTICATE OAUTHBEARER {response}"
	))));
}

#[test]
fn a_verified_email_that_only_a_catch_all_matches_opens_nothing() {
	let directory =
		Arc::new(gate_directory().with_catch_all([("example.org".to_string(), OPEN.to_string())]));
	let (verifier, pair, rng) = verifier_and_key();
	let response = bearer_response(&pair, &rng, "stranger@example.org");
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = session(dir.path(), directory).with_oauth(Some(verifier));
	assert!(!is_ok(&session.command_line(&format!(
		"a AUTHENTICATE OAUTHBEARER {response}"
	))));
}

#[test]
fn a_client_certificate_for_a_disabled_account_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = session(dir.path(), gate_directory_arc());
	session.set_client_identity(Some("bob@example.org".to_string()));
	let out = session.command_line("a AUTHENTICATE EXTERNAL =");
	assert!(!is_ok(&out), "EXTERNAL must not open a disabled account");
	assert_eq!(session.account(), None);
}

#[test]
fn a_client_certificate_admits_an_open_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = session(dir.path(), gate_directory_arc());
	session.set_client_identity(Some("alice@example.org".to_string()));
	assert!(is_ok(&session.command_line("a AUTHENTICATE EXTERNAL =")));
}
