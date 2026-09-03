//! Submission rate limiting through a real SMTP session. Split out of
//! `session_tests_auth.rs` only to stay under the per-file line limit; the
//! harness lives there.

use super::tests_auth::*;
use super::*;
use crate::smtp::auth::tests::fixture_password;

#[test]
fn submission_rate_limit_uses_per_domain_override() {
	// Per-domain limit is tighter than the server-wide default: the per-domain
	// value must win, so a second send within the per-domain budget is
	// allowed even though the global default would already reject it.
	let limiter = std::sync::Arc::new(crate::smtp::ratelimit::SendLimiter::new(60));
	let directory = Arc::new(
		Directory::new(
			["example.org".to_string()],
			[("alice@example.org".to_string(), "alice".to_string())],
		)
		.with_password_hashes([(
			"alice".to_string(),
			crate::smtp::auth::tests::hash(fixture_password()),
		)])
		.with_domain_submission_limits([("example.org".to_string(), 3)]),
	);
	let mut session = Session::new("mail.example.org")
		.with_directory(directory)
		.with_tls_active()
		.with_send_limiter(limiter)
		.with_global_submission_rate_limit(Some(1));
	session.command_line("EHLO client.example.org");
	session.command_line(&format!(
		"AUTH PLAIN {}",
		plain("alice", fixture_password())
	));

	// Three submissions fit under the per-domain limit of 3.
	for _ in 0..3 {
		assert_eq!(
			reply_code(&session.command_line("MAIL FROM:<alice@example.org>")),
			250
		);
		session.command_line("RSET");
	}
	// The fourth is deferred: the per-domain limit (3) wins over the global
	// (1), which would have deferred the second send.
	assert_eq!(
		reply_code(&session.command_line("MAIL FROM:<alice@example.org>")),
		450
	);
}

#[test]
fn submission_rate_limit_falls_back_to_global_when_domain_has_no_entry() {
	// Directory has no entry for example.org, but the global default is set:
	// the global wins (the conservative fallback).
	let limiter = std::sync::Arc::new(crate::smtp::ratelimit::SendLimiter::new(60));
	let mut session = Session::new("mail.example.org")
		.with_directory(auth_directory())
		.with_tls_active()
		.with_send_limiter(limiter)
		.with_global_submission_rate_limit(Some(1));
	session.command_line("EHLO client.example.org");
	session.command_line(&format!(
		"AUTH PLAIN {}",
		plain("alice", fixture_password())
	));

	assert_eq!(
		reply_code(&session.command_line("MAIL FROM:<alice@example.org>")),
		250
	);
	session.command_line("RSET");
	assert_eq!(
		reply_code(&session.command_line("MAIL FROM:<alice@example.org>")),
		450
	);
}

#[test]
fn submission_rate_limit_is_off_when_neither_domain_nor_global_is_set() {
	// No per-domain entry, no global default, but a limiter is still wired in
	// (e.g. the operator later adds a per-domain override). The session must
	// skip the call entirely: every send is accepted.
	let limiter = std::sync::Arc::new(crate::smtp::ratelimit::SendLimiter::new(60));
	let mut session = Session::new("mail.example.org")
		.with_directory(auth_directory())
		.with_tls_active()
		.with_send_limiter(limiter)
		.with_global_submission_rate_limit(None);
	session.command_line("EHLO client.example.org");
	session.command_line(&format!(
		"AUTH PLAIN {}",
		plain("alice", fixture_password())
	));

	for _ in 0..5 {
		assert_eq!(
			reply_code(&session.command_line("MAIL FROM:<alice@example.org>")),
			250
		);
		session.command_line("RSET");
	}
}

#[test]
fn submission_rate_limit_resolves_domain_from_account_address_not_first_domain() {
	// Two accounts, one on each of two hosted domains. The directory lists
	// example.com first; if the resolver naively read domains[0] it would
	// hand bob (in example.org) the example.com limit. The walk over the
	// account's own addresses must return the matching per-domain entry.
	let limiter = std::sync::Arc::new(crate::smtp::ratelimit::SendLimiter::new(60));
	let directory = Arc::new(
		Directory::new(
			["example.com".to_string(), "example.org".to_string()],
			[
				("alice@example.com".to_string(), "alice".to_string()),
				("bob@example.org".to_string(), "bob".to_string()),
			],
		)
		.with_password_hashes([
			(
				"alice".to_string(),
				crate::smtp::auth::tests::hash(fixture_password()),
			),
			(
				"bob".to_string(),
				crate::smtp::auth::tests::hash(fixture_password()),
			),
		])
		.with_domain_submission_limits([
			("example.com".to_string(), 1),
			("example.org".to_string(), 2),
		]),
	);

	// alice: per-domain 1. The second send within the window defers.
	let mut session = Session::new("mail.example.org")
		.with_directory(Arc::clone(&directory))
		.with_tls_active()
		.with_send_limiter(Arc::clone(&limiter));
	session.command_line("EHLO client.example.org");
	session.command_line(&format!(
		"AUTH PLAIN {}",
		plain("alice", fixture_password())
	));
	assert_eq!(
		reply_code(&session.command_line("MAIL FROM:<alice@example.com>")),
		250
	);
	session.command_line("RSET");
	assert_eq!(
		reply_code(&session.command_line("MAIL FROM:<alice@example.com>")),
		450
	);

	// bob: per-domain 2. The first two sends fit, the third defers. This
	// would be wrong if bob were charged the example.com limit of 1 (only
	// one send would pass).
	let mut session = Session::new("mail.example.org")
		.with_directory(Arc::clone(&directory))
		.with_tls_active()
		.with_send_limiter(Arc::clone(&limiter));
	session.command_line("EHLO client.example.org");
	session.command_line(&format!("AUTH PLAIN {}", plain("bob", fixture_password())));
	assert_eq!(
		reply_code(&session.command_line("MAIL FROM:<bob@example.org>")),
		250
	);
	session.command_line("RSET");
	assert_eq!(
		reply_code(&session.command_line("MAIL FROM:<bob@example.org>")),
		250
	);
	session.command_line("RSET");
	assert_eq!(
		reply_code(&session.command_line("MAIL FROM:<bob@example.org>")),
		450
	);
}

#[test]
fn external_authenticates_with_verified_client_cert() {
	let mut session = Session::new("mail.example.org")
		.with_directory(auth_directory())
		.with_tls_active();
	// The TLS layer recorded a verified certificate identity for this account.
	session.set_client_identity(Some("alice@example.org".to_string()));
	let ehlo = session.command_line("EHLO client.example.org");
	// The reply is deliberately not in the failure message: it comes out of
	// a session holding the fixture credentials, and a panic message is a
	// CI log.
	assert!(
		reply_text(&ehlo).contains("EXTERNAL"),
		"EXTERNAL must be advertised once a client cert is present"
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

#[test]
fn an_unauthenticated_client_over_the_ip_limit_gets_450() {
	// Two sends from one IP within the per-minute cap: both fit. The third
	// over the cap, with the session never authenticated, must get a 450.
	let limiter = std::sync::Arc::new(crate::smtp::ratelimit::SendLimiter::new(60));
	let mut session = Session::new("mail.example.org")
		.with_directory(inbound_test_directory())
		.with_inbound_ip_limit(limiter, 2);
	session.command_line("EHLO client.example.org");
	session.set_peer_ip(Some(std::net::IpAddr::from([192, 0, 2, 7])));
	assert_eq!(
		reply_code(&session.command_line("MAIL FROM:<attacker@example.org>")),
		250
	);
	session.command_line("RSET");
	assert_eq!(
		reply_code(&session.command_line("MAIL FROM:<attacker@example.org>")),
		250
	);
	session.command_line("RSET");
	// The third send is over the per-IP cap.
	assert_eq!(
		reply_code(&session.command_line("MAIL FROM:<attacker@example.org>")),
		450
	);
}

#[test]
fn a_sender_over_the_sender_limit_gets_450_from_any_client() {
	// The per-sender limiter is keyed by the lowercased reverse path: a
	// fixed sender behind two different client IPs must still hit the cap
	// across the window.
	let limiter = std::sync::Arc::new(crate::smtp::ratelimit::SendLimiter::new(60));
	let directory = inbound_test_directory();
	// First peer: sends two messages fitting under the cap of 2.
	let mut session_a = Session::new("mail.example.org")
		.with_directory(Arc::clone(&directory))
		.with_inbound_sender_limit(Arc::clone(&limiter), 2);
	session_a.command_line("EHLO a.example.org");
	session_a.set_peer_ip(Some(std::net::IpAddr::from([198, 51, 100, 10])));
	assert_eq!(
		reply_code(&session_a.command_line("MAIL FROM:<victim@example.org>")),
		250
	);
	session_a.command_line("RSET");
	assert_eq!(
		reply_code(&session_a.command_line("MAIL FROM:<Victim@Example.org>")),
		250,
		"second send from the same lowercase sender must fit"
	);
	// Second peer from another address uses a fresh session, so the per-IP
	// limit is irrelevant: the per-sender budget is shared across clients.
	let mut session_b = Session::new("mail.example.org")
		.with_directory(Arc::clone(&directory))
		.with_inbound_sender_limit(Arc::clone(&limiter), 2);
	session_b.command_line("EHLO b.example.org");
	session_b.set_peer_ip(Some(std::net::IpAddr::from([198, 51, 100, 20])));
	assert_eq!(
		reply_code(&session_b.command_line("MAIL FROM:<victim@example.org>")),
		450,
		"third send across clients must be deferred for the same sender"
	);
}

#[test]
fn the_null_sender_is_never_sender_limited() {
	// Bounces use the null reverse-path `<>` (RFC 5321 §4.5.5). Charging
	// that against the per-sender budget would let a misconfigured
	// upstream eat a legitimate sender's allowance on the first bounce.
	let limiter = std::sync::Arc::new(crate::smtp::ratelimit::SendLimiter::new(60));
	let mut session = Session::new("mail.example.org")
		.with_directory(inbound_test_directory())
		.with_inbound_sender_limit(limiter, 1);
	session.command_line("EHLO client.example.org");
	session.set_peer_ip(Some(std::net::IpAddr::from([192, 0, 2, 7])));
	// Five null-sender MAIL FROMs in a row: the per-sender cap is 1 but
	// every reply is 250 because the null sender is skipped.
	for _ in 0..5 {
		assert_eq!(reply_code(&session.command_line("MAIL FROM:<>")), 250);
		session.command_line("RSET");
	}
}

#[test]
fn an_authenticated_session_is_not_subject_to_the_inbound_limits() {
	// The inbound per-IP and per-sender limits are for *unauthenticated*
	// traffic. A session that has authenticated must be charged against
	// its per-account submission limit only; even one wired to 0 must
	// never blow up on the inbound check.
	let ip_limiter = std::sync::Arc::new(crate::smtp::ratelimit::SendLimiter::new(60));
	let sender_limiter = std::sync::Arc::new(crate::smtp::ratelimit::SendLimiter::new(60));
	let mut session = Session::new("mail.example.org")
		.with_directory(auth_directory())
		.with_tls_active()
		.with_inbound_ip_limit(ip_limiter, 1)
		.with_inbound_sender_limit(sender_limiter, 1);
	session.command_line("EHLO client.example.org");
	session.command_line(&format!(
		"AUTH PLAIN {}",
		plain("alice", fixture_password())
	));
	// Three authenticated MAIL FROMs in a row: under the per-account cap
	// (no submission limit configured), the inbound caps do nothing.
	for _ in 0..3 {
		assert_eq!(
			reply_code(&session.command_line("MAIL FROM:<alice@example.org>")),
			250
		);
		session.command_line("RSET");
	}
}

fn inbound_test_directory() -> Arc<Directory> {
	Arc::new(Directory::new(
		["example.org".to_string()],
		[
			("alice@example.org".to_string(), "alice".to_string()),
			("attacker@example.org".to_string(), "attacker".to_string()),
			("victim@example.org".to_string(), "victim".to_string()),
		],
	))
}
