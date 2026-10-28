//! The subscriptions `migrate imap` leaves in the destination account.
//!
//! A client that lists only the subscribed mailboxes (Roundcube and many
//! others) shows nothing but INBOX when the folders the migration copied are
//! not subscribed, so every folder the run puts in the destination is
//! subscribed too.

use super::fake_server::{FakeServer, Mode};
use super::run_tests::{folders, migrate, settings};
use crate::imap::mailbox;

/// Whether `name` is in the subscriptions of the account.
fn subscribed(dir: &std::path::Path, name: &str) -> bool {
	mailbox::list_subscribed(dir, "alice")
		.iter()
		.any(|subscription| subscription == name)
}

#[tokio::test]
async fn every_folder_the_run_copies_is_subscribed() {
	let server = FakeServer::start(Mode::Tls, '.', folders()).await;
	let dir = tempfile::tempdir().expect("tempdir");
	let (_, error) = migrate(&server, dir.path(), &settings()).await;
	assert!(error.is_none(), "{error:?}");

	for folder in ["INBOX", "Sent", "Junk", "Work"] {
		assert!(
			subscribed(dir.path(), folder),
			"{folder} was copied but is not subscribed"
		);
	}
	assert!(
		!subscribed(dir.path(), "Shelf"),
		"a folder that was skipped is not subscribed"
	);
}

#[tokio::test]
async fn a_folder_the_account_already_had_is_subscribed_too() {
	let server = FakeServer::start(Mode::Tls, '.', folders()).await;
	let dir = tempfile::tempdir().expect("tempdir");
	// An account that exists already has the standard folders, so the
	// migration fills one of them instead of creating it.
	mailbox::ensure_defaults(dir.path(), "alice").expect("defaults");
	let (_, error) = migrate(&server, dir.path(), &settings()).await;
	assert!(error.is_none(), "{error:?}");

	assert!(
		subscribed(dir.path(), "Sent"),
		"the Sent folder the migration filled is not subscribed"
	);
}
