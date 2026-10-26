//! Every SMTP AUTH mechanism applies the same account rules: a disabled
//! account, an account with a second factor and an address in a switched-off
//! domain are refused by PLAIN, LOGIN, SCRAM, OAUTHBEARER and EXTERNAL alike.

use super::tests_scram::{b64, reply_code};
use super::tests_scram_bans::{decode_server_first, scram_challenge_text};
use super::*;
use crate::smtp::directory::gate_fixture::*;
use crate::test_fixtures as fixtures;

fn session(directory: Arc<Directory>) -> Session {
	let mut session = Session::new("mail.example.org")
		.with_directory(directory)
		.with_tls_active()
		.with_scram_nonce(fixtures::nonce());
	session.command_line("EHLO client.example.org");
	session
}

fn plain(session: &mut Session, login: &str, password: &str) -> u16 {
	let response = b64(&format!("\0{login}\0{password}"));
	reply_code(&session.command_line(&format!("AUTH PLAIN {response}")))
}

fn login(session: &mut Session, user: &str, password: &str) -> u16 {
	assert_eq!(reply_code(&session.command_line("AUTH LOGIN")), 334);
	assert_eq!(reply_code(&session.auth_line(&b64(user))), 334);
	reply_code(&session.auth_line(&b64(password)))
}

/// Run SCRAM-SHA-256 for `user` with `password`; the code of the last reply.
fn scram(session: &mut Session, user: &str, password: &str) -> u16 {
	let bare = format!("n={user},r=CN");
	let first = session.command_line(&format!(
		"AUTH SCRAM-SHA-256 {}",
		b64(&format!("n,,{bare}"))
	));
	if reply_code(&first) != 334 {
		return reply_code(&first);
	}
	let server_first = decode_server_first(&scram_challenge_text(&first));
	let client_final = scram_client_final(&bare, &server_first, password);
	reply_code(&session.auth_line(&b64(&client_final)))
}

#[test]
fn scram_admits_an_open_account() {
	let mut session = session(gate_directory_arc());
	assert_eq!(scram(&mut session, OPEN, fixtures::password()), 235);
	assert_eq!(session.authenticated(), Some(OPEN));
}

#[test]
fn scram_refuses_a_disabled_account_that_proves_the_password() {
	let mut session = session(gate_directory_arc());
	let code = scram(&mut session, DISABLED, fixtures::password());
	assert_eq!(code, 535, "a disabled account must not finish SCRAM");
	assert_eq!(session.authenticated(), None);
}

#[test]
fn scram_refuses_an_account_with_a_second_factor() {
	let mut session = session(gate_directory_arc());
	let code = scram(&mut session, TWO_FACTOR, fixtures::password());
	assert_eq!(code, 535, "SCRAM cannot carry the TOTP code");
	assert_eq!(session.authenticated(), None);
}

#[test]
fn scram_refuses_an_address_in_a_switched_off_domain() {
	let mut session = session(gate_directory_arc());
	let user = format!("{OFF_DOMAIN_ACCOUNT}@{OFF_DOMAIN}");
	assert_eq!(scram(&mut session, &user, fixtures::password()), 535);
	assert_eq!(session.authenticated(), None);
}

#[test]
fn the_account_name_still_signs_in_when_its_domain_is_switched_off() {
	let mut session = session(gate_directory_arc());
	assert_eq!(
		scram(&mut session, OFF_DOMAIN_ACCOUNT, fixtures::password()),
		235
	);
}

#[test]
fn password_mechanisms_refuse_the_same_accounts() {
	let password = fixtures::password();
	let off_address = format!("{OFF_DOMAIN_ACCOUNT}@{OFF_DOMAIN}");
	for user in [DISABLED, TWO_FACTOR, off_address.as_str()] {
		let mut by_plain = session(gate_directory_arc());
		assert_eq!(plain(&mut by_plain, user, password), 535, "PLAIN {user}");
		assert_eq!(by_plain.authenticated(), None);
		let mut by_login = session(gate_directory_arc());
		assert_eq!(login(&mut by_login, user, password), 535, "LOGIN {user}");
		assert_eq!(by_login.authenticated(), None);
	}
}

#[test]
fn the_two_factor_code_opens_the_password_mechanisms() {
	let with_code = format!("{}{}", fixtures::password(), current_totp_code());
	let mut by_plain = session(gate_directory_arc());
	assert_eq!(plain(&mut by_plain, TWO_FACTOR, &with_code), 235);
	let mut by_login = session(gate_directory_arc());
	assert_eq!(login(&mut by_login, TWO_FACTOR, &with_code), 235);
}

#[test]
fn an_app_password_that_has_expired_or_is_off_its_network_opens_nothing() {
	let (directory, expired, elsewhere) = gate_directory_with_app_passwords();
	let directory = Arc::new(directory);
	for secret in [expired, elsewhere] {
		let mut session = session(directory.clone());
		session.set_peer_ip(Some("203.0.113.9".parse().expect("peer")));
		assert_eq!(plain(&mut session, OPEN, secret), 535);
		assert_eq!(session.authenticated(), None);
	}
}

fn oauth_session(email: &str) -> (Session, String) {
	let (verifier, pair, rng) = verifier_and_key();
	let response = bearer_response(&pair, &rng, email);
	(session(gate_directory_arc()).with_oauth(verifier), response)
}

#[test]
fn a_bearer_token_admits_an_open_account() {
	let (mut session, response) = oauth_session("alice@example.org");
	assert_eq!(
		reply_code(&session.command_line(&format!("AUTH OAUTHBEARER {response}"))),
		235
	);
}

#[test]
fn a_bearer_token_for_a_disabled_account_is_refused() {
	for mechanism in ["OAUTHBEARER", "XOAUTH2"] {
		let (mut session, response) = oauth_session("bob@example.org");
		let code = reply_code(&session.command_line(&format!("AUTH {mechanism} {response}")));
		assert_eq!(code, 535, "{mechanism} must not open a disabled account");
		assert_eq!(session.authenticated(), None);
	}
}

fn authenticate(mut session: Session, response: &str) -> u16 {
	reply_code(&session.command_line(&format!("AUTH OAUTHBEARER {response}")))
}

#[test]
fn a_bearer_token_with_an_unverified_or_unstated_email_opens_nothing() {
	for verified in [Some(false), None] {
		let (verifier, pair, rng) = verifier_and_key();
		let response = bearer_response_verified(&pair, &rng, "alice@example.org", verified);
		let session = session(gate_directory_arc()).with_oauth(verifier);
		assert_eq!(authenticate(session, &response), 535, "{verified:?}");
	}
}

#[test]
fn a_bearer_token_does_not_skip_the_second_factor() {
	let (verifier, pair, rng) = verifier_and_key();
	let response = bearer_response(&pair, &rng, "carol@example.org");
	let session = session(gate_directory_arc()).with_oauth(verifier);
	assert_eq!(authenticate(session, &response), 535);
}

#[test]
fn a_bearer_token_opens_a_second_factor_account_when_the_provider_enforces_it() {
	let (verifier, pair, rng) = verifier_and_key_with(true);
	let response = bearer_response(&pair, &rng, "carol@example.org");
	let session = session(gate_directory_arc()).with_oauth(verifier);
	assert_eq!(authenticate(session, &response), 235);
}

#[test]
fn a_token_of_the_built_in_server_opens_a_second_factor_account() {
	let (verifier, pair, rng) = own_verifier_and_key();
	let response = own_bearer_response(&pair, &rng, TWO_FACTOR);
	let session = session(gate_directory_arc()).with_oauth(verifier);
	assert_eq!(authenticate(session, &response), 235);
}

#[test]
fn a_token_of_the_built_in_server_for_a_disabled_or_unknown_account_opens_nothing() {
	for account in [DISABLED, "nobody"] {
		let (verifier, pair, rng) = own_verifier_and_key();
		let response = own_bearer_response(&pair, &rng, account);
		let session = session(gate_directory_arc()).with_oauth(verifier);
		assert_eq!(
			authenticate(session, &response),
			535,
			"the sign-in is refused"
		);
	}
}

#[test]
fn a_verified_email_that_only_a_catch_all_or_a_sub_address_matches_opens_nothing() {
	let directory =
		Arc::new(gate_directory().with_catch_all([("example.org".to_string(), OPEN.to_string())]));
	for email in ["stranger@example.org", "alice+tag@example.org"] {
		let (verifier, pair, rng) = verifier_and_key();
		let response = bearer_response(&pair, &rng, email);
		let session = session(directory.clone()).with_oauth(verifier);
		assert_eq!(authenticate(session, &response), 535, "{email}");
	}
}

#[test]
fn a_client_certificate_for_a_disabled_account_is_refused() {
	let mut session = session(gate_directory_arc());
	session.set_client_identity(Some("bob@example.org".to_string()));
	let code = reply_code(&session.command_line("AUTH EXTERNAL ="));
	assert_eq!(code, 535, "EXTERNAL must not open a disabled account");
	assert_eq!(session.authenticated(), None);
}

#[test]
fn a_client_certificate_admits_an_open_account() {
	let mut session = session(gate_directory_arc());
	session.set_client_identity(Some("alice@example.org".to_string()));
	assert_eq!(reply_code(&session.command_line("AUTH EXTERNAL =")), 235);
}
