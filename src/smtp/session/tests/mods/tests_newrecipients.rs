//! Submission rate limiting on the per-account rolling 24h
//! first-time-recipient cap. The cap is enforced at end-of-DATA
//! because only there is the full recipient list in scope; this
//! file keeps the harness local instead of inflating the basic
//! session tests past the per-file line limit.

use std::sync::Arc;

use super::auth::tests_auth::*;
use super::*;
use crate::smtp::auth::tests::base::fixture_password;

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
	let mut cap = super::cap::Cap::empty().with_correspondents(store);
	if let Some(limit) = limit {
		cap = cap.with_daily_new_recipients(Some(limit));
	}
	session.with_cap(cap)
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
	// The sender's own From: an authenticated submission must carry it.
	assert!(session.data_line(b"From: alice@example.org").is_none());
	assert!(session.data_line(b"").is_none());
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

/// Put a file where the store's directory is, so that taking its lock fails.
fn break_store(dir: &std::path::Path) {
	std::fs::rename(dir.join("correspondents"), dir.join("correspondents.away")).expect("move");
	std::fs::write(dir.join("correspondents"), b"").expect("file in its place");
}

/// A cap that cannot be checked defers the submission with a `451`, and
/// delivers nothing; once the store works the cap is the `450` again.
#[test]
fn a_cap_that_cannot_be_checked_defers_the_submission() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = Arc::new(crate::storage::CorrespondentStore::open(dir.path()).expect("store"));
	break_store(dir.path());
	let mut session = alice_session_with_correspondents(store, Some(2));
	assert_eq!(submit_to(&mut session, &["b@elsewhere.example"]), 451);
}

#[test]
fn a_cap_with_no_store_defers_the_submission() {
	let mut session = tls_session();
	session.command_line(&format!(
		"AUTH PLAIN {}",
		plain("alice", fixture_password())
	));
	let mut session = session.with_cap(super::cap::Cap::empty().with_daily_new_recipients(Some(2)));
	assert_eq!(submit_to(&mut session, &["b@elsewhere.example"]), 451);
}

/// Without a cap the store only keeps a record, and a failure there does not
/// stop the message.
#[test]
fn without_a_cap_a_failing_store_does_not_defer() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = Arc::new(crate::storage::CorrespondentStore::open(dir.path()).expect("store"));
	break_store(dir.path());
	let mut session = alice_session_with_correspondents(store, None);
	assert_eq!(submit_to(&mut session, &["b@elsewhere.example"]), 250);
}
