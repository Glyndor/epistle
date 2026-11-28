//! A submission is charged to the tenant of every address it is sent under,
//! not only to the tenants of the account's own addresses.

use super::super::auth::tests_auth::{plain, reply_code, reply_text};
use super::*;
use crate::smtp::auth::tests::base::fixture_password;
use crate::smtp::directory::AliasSpec;

/// An address of the account, in the tenant with no limit.
const OWN: &str = "alice@example.org";
/// A list the account may send as, in the limited tenant.
const LIST: &str = "ops@other.example";
/// Another account's address in the limited tenant.
const FOREIGN: &str = "boss@other.example";

/// `example.org` is a tenant with no limit, `other.example` one that may
/// send one recipient a minute. `alice` has no address there, only the list.
fn session() -> Session {
	let directory = Directory::new(
		["example.org".to_string(), "other.example".to_string()],
		[
			(OWN.to_string(), "alice".to_string()),
			(FOREIGN.to_string(), "bob".to_string()),
		],
	)
	.with_aliases([(
		LIST.to_string(),
		AliasSpec {
			members: vec![OWN.to_string()],
			senders: Vec::new(),
			hidden: true,
			list_id: None,
		},
	)])
	.with_password_hashes([(
		"alice".to_string(),
		crate::smtp::auth::tests::base::hash(fixture_password()),
	)]);
	let tenant = |name: &str, domain: &str, per_min: Option<u32>| crate::config::Tenant {
		name: Some(name.to_string()),
		domains: vec![domain.to_string()],
		quota_bytes: None,
		max_accounts: None,
		max_domains: None,
		submission_rate_limit_per_min: per_min,
		encryption_key_file: None,
		webhook: None,
	};
	let limits = Arc::new(crate::api::TenantLimits::from_config(&[
		tenant("a", "example.org", None),
		tenant("b", "other.example", Some(1)),
	]));
	let mut session = Session::new("mail.example.org")
		.with_directory(Arc::new(directory))
		.with_tls_active()
		.with_tenant_limits(limits);
	session.command_line("EHLO client.example.org");
	session.command_line(&format!(
		"AUTH PLAIN {}",
		plain("alice", fixture_password())
	));
	assert_eq!(session.authenticated(), Some("alice"));
	session
}

/// One message to a remote recipient: the `MAIL FROM` reply code, and the
/// reply to the end of the data when the transaction got that far.
fn submit(session: &mut Session, mail_from: &str, headers: &[&str]) -> (u16, Option<String>) {
	let mail = reply_code(&session.command_line(&format!("MAIL FROM:<{mail_from}>")));
	if mail != 250 {
		return (mail, None);
	}
	assert_eq!(
		reply_code(&session.command_line("RCPT TO:<someone@elsewhere.example>")),
		250
	);
	assert_eq!(reply_code(&session.command_line("DATA")), 354);
	for line in headers.iter().chain(&["", "hi"]) {
		assert!(session.data_line(line.as_bytes()).is_none());
	}
	let end = session.data_line(b".").expect("end of data");
	(mail, Some(reply_text(&end)))
}

#[track_caller]
fn accepted(session: &mut Session, mail_from: &str, headers: &[&str]) {
	let (mail, end) = submit(session, mail_from, headers);
	assert_eq!(mail, 250, "{mail_from} {headers:?}");
	let end = end.expect("end of data");
	assert!(end.starts_with("250 "), "{mail_from} {headers:?}: {end}");
}

const OVER_LIMIT: &str = "450 4.7.1 sending rate limit exceeded; retry later\r\n";

#[test]
fn an_envelope_sender_in_another_tenant_is_charged_to_it() {
	let mut session = session();
	let from = format!("From: {OWN}");
	accepted(&mut session, LIST, &[&from]);
	// The tenant is spent, so the envelope sender is refused outright.
	assert_eq!(submit(&mut session, LIST, &[&from]), (450, None));
}

#[test]
fn an_author_in_another_tenant_is_charged_to_it() {
	let mut session = session();
	let from = format!("From: {LIST}");
	accepted(&mut session, OWN, &[&from]);
	// `MAIL FROM` cannot know the author yet; the end of the data does.
	assert_eq!(
		submit(&mut session, OWN, &[&from]),
		(250, Some(OVER_LIMIT.to_string()))
	);
}

#[test]
fn an_owned_sender_field_in_another_tenant_is_charged_to_it() {
	let mut session = session();
	let from = format!("From: {OWN}");
	let sender = format!("Sender: {LIST}");
	accepted(&mut session, OWN, &[&from, &sender]);
	assert_eq!(
		submit(&mut session, OWN, &[&from, &sender]),
		(250, Some(OVER_LIMIT.to_string()))
	);
}

#[test]
fn a_sender_field_the_account_does_not_own_spends_nobody_else() {
	let mut session = session();
	let from = format!("From: {OWN}");
	let sender = format!("Sender: {FOREIGN}");
	for _ in 0..3 {
		accepted(&mut session, OWN, &[&from, &sender]);
	}
	// The limited tenant still has its one recipient.
	accepted(&mut session, LIST, &[&from]);
}

#[test]
fn a_submission_under_the_account_own_domain_does_not_touch_the_other_tenant() {
	let mut session = session();
	let from = format!("From: {OWN}");
	for _ in 0..3 {
		accepted(&mut session, OWN, &[&from]);
	}
}
