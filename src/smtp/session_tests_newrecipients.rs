//! Submission rate limiting on the per-account rolling 24h
//! first-time-recipient cap. The cap is enforced at end-of-DATA
//! because only there is the full recipient list in scope; this
//! file keeps the harness local instead of inflating the basic
//! session tests past the per-file line limit.

use std::sync::Arc;

use super::tests_auth::*;
use super::*;
use crate::smtp::auth::tests::fixture_password;

fn alice_session_with_correspondents(
	store: Arc<crate::storage::CorrespondentStore>,
	limit: Option<u32>,
) -> Session {
	let mut session = tls_session();
	session.command_line(&format!(
		"AUTH PLAIN {}",
		plain("alice", fixture_password())
	));
	assert_eq!(session.authenticated(), Some("alice"));
	session = session.with_correspondents(store);
	if limit.is_some() {
		session = session.with_daily_new_recipients(limit);
	}
	session
}

fn submit_to(session: &mut Session, recipients: &[&str]) -> u16 {
	assert_eq!(
		reply_code(&session.command_line("MAIL FROM:<alice@example.org>")),
		250
	);
	for recipient in recipients {
		assert_eq!(
			reply_code(&session.command_line(&format!("RCPT TO:<{recipient}>"))),
			250
		);
	}
	assert!(matches!(
		session.command_line("DATA"),
		Action::CollectData(_)
	));
	let Some(action) = session.data_line(b".") else {
		panic!("DATA did not produce a final action");
	};
	reply_code(&action)
}

/// Three new recipients in one message and a daily cap of 2: the
/// first submission is refused at end-of-DATA with `450 4.7.1`.
#[test]
fn a_submission_over_the_daily_new_recipient_limit_is_deferred() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = Arc::new(crate::storage::CorrespondentStore::open(dir.path()).expect("store"));
	let mut session = alice_session_with_correspondents(store, Some(2));
	let code = submit_to(
		&mut session,
		&[
			"b@elsewhere.example",
			"c@elsewhere.example",
			"d@elsewhere.example",
		],
	);
	assert_eq!(code, 450, "exceeding the daily cap must defer");
}

/// Once a recipient has been recorded, it does not count toward the
/// daily cap on the next submission. Three known recipients in one
/// message are not refused.
#[test]
fn known_recipients_do_not_count_against_the_limit() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = Arc::new(crate::storage::CorrespondentStore::open(dir.path()).expect("store"));
	// Pre-record the recipients so the message to them is fully
	// known.
	store
		.record(
			"alice",
			&[
				"b@elsewhere.example",
				"c@elsewhere.example",
				"d@elsewhere.example",
			],
		)
		.expect("pre-record");

	let mut session = alice_session_with_correspondents(store, Some(2));
	let code = submit_to(
		&mut session,
		&[
			"b@elsewhere.example",
			"c@elsewhere.example",
			"d@elsewhere.example",
		],
	);
	assert_eq!(code, 250, "every recipient is already known");
}
