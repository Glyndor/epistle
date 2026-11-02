//! The dns-01 journal: a record published by a run that stopped before its
//! withdrawal is withdrawn by the next start, from the zone it was published
//! in and with the value it was published with.

use super::*;
use crate::acme::challenge::fake_zone::{FakeZone, dns01};
use std::sync::atomic::Ordering;

const DOMAIN: &str = "mail.example.org";
const TOKEN: &str = "token-aaaa";

fn key() -> AccountKey {
	AccountKey::generate().expect("key").0
}

/// The one write of `verb` the provider saw, without its verb.
fn only(calls: &[String], verb: &str) -> String {
	let matching: Vec<&String> = calls.iter().filter(|call| call.starts_with(verb)).collect();
	assert_eq!(matching.len(), 1, "{verb} calls: {calls:?}");
	matching[0][verb.len()..].to_string()
}

fn journal_entries(path: &std::path::Path) -> usize {
	match std::fs::read(path) {
		Ok(bytes) => serde_json::from_slice::<Vec<serde_json::Value>>(&bytes)
			.expect("journal")
			.len(),
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
		Err(error) => panic!("journal: {error}"),
	}
}

#[tokio::test]
async fn a_published_record_stays_in_the_journal_until_the_provider_removed_it() {
	let dir = tempfile::tempdir().expect("directory");
	let path = journal_path(dir.path());
	let provider = FakeZone::new(&["example.org"]);
	let responder = dns01(&provider).with_journal(path.clone());
	let key = key();

	responder
		.publish(DOMAIN, TOKEN, &key)
		.await
		.expect("publish");
	assert_eq!(journal_entries(&path), 1, "published and journaled");

	responder.withdraw(DOMAIN, TOKEN, &key).await;
	assert_eq!(provider.deletes().len(), 1);
	assert!(!path.exists(), "nothing is pending, so the journal is gone");
}

#[tokio::test]
async fn a_record_a_stopped_run_left_is_withdrawn_at_the_next_start() {
	let dir = tempfile::tempdir().expect("directory");
	let path = journal_path(dir.path());
	let first = FakeZone::new(&["example.org"]);
	// The first run publishes and stops without withdrawing, the way a
	// process killed in the middle of an order stops.
	dns01(&first)
		.with_journal(path.clone())
		.publish(DOMAIN, TOKEN, &key())
		.await
		.expect("publish");

	// The next run has a fresh process and a provider whose lookup fails:
	// the record is removed from the zone the journal names, with the value
	// the first run published, and nothing is asked of the provider first.
	let second = FakeZone::new(&["example.org"]);
	second.lookup_fails.store(true, Ordering::Relaxed);
	let restarted = dns01(&second).with_journal(path.clone());
	restarted.withdraw_pending().await;

	assert_eq!(
		only(&second.calls(), "delete "),
		only(&first.calls(), "upsert ")
	);
	assert!(!path.exists(), "the journal is empty after the withdrawal");
}

#[tokio::test]
async fn a_delete_that_failed_is_kept_for_the_next_start() {
	let dir = tempfile::tempdir().expect("directory");
	let path = journal_path(dir.path());
	let provider = FakeZone::new(&["example.org"]);
	let responder = dns01(&provider).with_journal(path.clone());
	let key = key();
	responder
		.publish(DOMAIN, TOKEN, &key)
		.await
		.expect("publish");

	provider.delete_fails.store(true, Ordering::Relaxed);
	responder.withdraw(DOMAIN, TOKEN, &key).await;
	assert_eq!(provider.deletes().len(), 1, "the delete was tried");
	assert_eq!(journal_entries(&path), 1, "and the record is still pending");

	let next = FakeZone::new(&["example.org"]);
	dns01(&next)
		.with_journal(path.clone())
		.withdraw_pending()
		.await;
	assert_eq!(next.deletes().len(), 1);
	assert!(!path.exists());
}

#[tokio::test]
async fn a_journal_that_cannot_be_written_stops_the_publish_before_the_provider() {
	let dir = tempfile::tempdir().expect("directory");
	// The journal's directory is a file, so the journal cannot be written.
	std::fs::write(dir.path().join("acme"), b"not a directory").expect("file");
	let provider = FakeZone::new(&["example.org"]);
	let responder = dns01(&provider).with_journal(journal_path(dir.path()));

	let refused = responder.publish(DOMAIN, TOKEN, &key()).await;

	assert!(
		matches!(&refused, Err(AcmeError::Protocol(message)) if message.contains("journal")),
		"{refused:?}"
	);
	assert!(provider.calls().is_empty(), "calls: {:?}", provider.calls());
}

#[tokio::test]
async fn with_nothing_pending_the_start_asks_the_provider_nothing() {
	let dir = tempfile::tempdir().expect("directory");
	let provider = FakeZone::new(&["example.org"]);
	dns01(&provider)
		.with_journal(journal_path(dir.path()))
		.withdraw_pending()
		.await;
	assert!(provider.calls().is_empty(), "calls: {:?}", provider.calls());
	assert!(!journal_path(dir.path()).exists());
}
