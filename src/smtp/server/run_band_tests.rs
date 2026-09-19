//! Unit tests for the per-account scoring scope picker.
//!
//! The picker is the only place that decides which corpus scope the
//! uncertain-band scorer asks about, so the seven cases below pin the
//! contract end-to-end: account owner, case folding, multi-target
//! alias, domain alias, remote recipient skipped ahead of a local one,
//! unknown local user, and empty envelope.

use std::sync::Arc;

use super::scoring_account;
use crate::smtp::directory::{AliasSpec, Directory};

/// Build the test directory: account `alice` owns `alice@example.org`,
/// account `bob` owns `bob@example.org`, a multi-target alias
/// `sales@example.org` fans out to `bob` (its first target), and
/// `example.net` is a domain alias for `example.org`.
fn directory() -> Directory {
	let aliases = [(
		"sales@example.org".to_string(),
		AliasSpec {
			members: vec![
				"bob@example.org".to_string(),
				"alice@example.org".to_string(),
			],
			senders: Vec::new(),
			hidden: false,
			list_id: None,
		},
	)];
	Directory::new(
		["example.org".to_string()],
		[
			("alice@example.org".to_string(), "alice".to_string()),
			("bob@example.org".to_string(), "bob".to_string()),
		],
	)
	.with_aliases(aliases)
	.with_domain_aliases([("example.net".to_string(), "example.org".to_string())])
}

#[test]
fn owner_address_resolves_to_their_account_name() {
	let dir = directory();
	let recipients = vec!["alice@example.org".to_string()];
	assert_eq!(scoring_account(&dir, &recipients).as_deref(), Some("alice"));
}

#[test]
fn recipient_case_does_not_change_the_account() {
	let dir = directory();
	let recipients = vec!["ALICE@EXAMPLE.ORG".to_string()];
	assert_eq!(scoring_account(&dir, &recipients).as_deref(), Some("alice"));
}

#[test]
fn multi_target_alias_picks_the_first_target() {
	let dir = directory();
	let recipients = vec!["sales@example.org".to_string()];
	assert_eq!(scoring_account(&dir, &recipients).as_deref(), Some("bob"));
}

#[test]
fn domain_alias_resolves_through_to_the_target_domain() {
	let dir = directory();
	let recipients = vec!["alice@example.net".to_string()];
	assert_eq!(scoring_account(&dir, &recipients).as_deref(), Some("alice"));
}

#[test]
fn a_remote_recipient_is_skipped_in_favour_of_a_later_local_one() {
	let dir = directory();
	let recipients = vec![
		"someone@remote.test".to_string(),
		"alice@example.org".to_string(),
	];
	assert_eq!(scoring_account(&dir, &recipients).as_deref(), Some("alice"));
}

#[test]
fn an_unknown_local_user_yields_no_account() {
	let dir = directory();
	let recipients = vec!["nobody@example.org".to_string()];
	assert_eq!(scoring_account(&dir, &recipients), None);
}

#[test]
fn an_empty_recipient_list_yields_no_account() {
	let dir = directory();
	let recipients: Vec<String> = Vec::new();
	assert_eq!(scoring_account(&dir, &recipients), None);
}

/// Regression: IMAP/JMAP training writes the corpus under the account
/// name (`alice`), and the SMTP uncertain-band scorer reads it under
/// the same string. The two paths are wired through independent call
/// sites (`enqueue_junk_transition` here, `scoring_account` on the SMTP
/// side), and a future drift, say training switching to the envelope
/// address, would make the per-account corpus unreachable for every
/// inbound message. The test exercises both ends and asserts they saw
/// the same scope string.
#[tokio::test]
async fn imap_training_and_smtp_scoring_agree_on_the_scope() {
	use crate::antispam::trainer::RecordingTrainer;
	use crate::imap::junk_trainer::enqueue_junk_transition;
	use crate::imap::keyword::JUNK;
	use crate::imap::mailbox::Flag;

	let dir = directory();
	let recipients = vec!["alice@example.org".to_string()];

	// SMTP side: the band picks `alice` as the scope.
	let scope = scoring_account(&dir, &recipients);
	assert_eq!(
		scope.as_deref(),
		Some("alice"),
		"SMTP scope for alice@example.org"
	);

	// IMAP side: a `$Junk` keyword change for account `alice` writes
	// the message under the same scope the SMTP band just picked.
	let message_path = std::path::PathBuf::from("/dev/null");
	let trainer = Arc::new(RecordingTrainer::new());
	let metrics = Arc::new(crate::metrics::Metrics::new());
	let (queue, receiver) = crate::antispam::training_queue::TrainingQueue::bounded(8, metrics);
	let junk = Flag::parse(JUNK).expect("parse $Junk");
	assert!(
		enqueue_junk_transition(
			&queue,
			scope.as_deref().unwrap(),
			&[],
			std::slice::from_ref(&junk),
			message_path
		),
		"the $Junk change must submit a training job"
	);
	let handle = Arc::clone(&trainer) as Arc<dyn crate::antispam::trainer::BayesTrainer>;
	tokio::spawn(async move {
		crate::antispam::training_queue::run_worker(
			receiver,
			handle,
			crate::storage::MessageCrypto::disabled(),
		)
		.await;
	});
	trainer.await_one_call().await;
	let calls = trainer.calls();
	assert_eq!(calls.len(), 1, "exactly one train call recorded");
	assert_eq!(
		calls[0].0, "alice",
		"IMAP training must use the same scope the SMTP band picked"
	);
}
