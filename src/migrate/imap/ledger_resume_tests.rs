//! Scenarios of a rerun that must not import what the local mailbox no longer
//! holds, against the in-process fake server.

use super::MigrateError;
use super::fake_server::{FakeServer, Message, Mode, USER};
use super::run_tests;
use super::run_tests::{DATE_1, DATE_2, local, mail, migrate, settings};
use super::state::StateDir;

/// One INBOX with `messages`, and no other folder.
fn inbox(messages: Vec<Message>) -> Vec<super::fake_server::Folder> {
	let mut all = run_tests::folders();
	all[0].messages = messages;
	all.truncate(1);
	all
}

fn states(dir: &std::path::Path) -> StateDir {
	StateDir::open(dir, "alice", &format!("{USER}@mail.example.org")).expect("state")
}

/// What a kill between storing a message and recording it leaves: the state
/// still points before the batch and asks for the folder to be replayed.
fn replay_from_the_start(dir: &std::path::Path) {
	let states = states(dir);
	let mut saved = states.load(b"INBOX").expect("load").expect("saved");
	saved.last_uid = 0;
	saved.in_progress = true;
	states.save(b"INBOX", &saved).expect("save");
}

/// Remove the local copy whose body is `body`, the way a user deletes a
/// message from the new mailbox.
fn remove_local(dir: &std::path::Path, body: &[u8]) {
	let mailbox = crate::imap::mailbox::mailbox_dir(dir, "alice", "INBOX").expect("mailbox");
	let crypto = crate::storage::MessageCrypto::disabled();
	for entry in std::fs::read_dir(&mailbox).expect("entries") {
		let path = entry.expect("entry").path();
		if path.extension().is_none_or(|extension| extension != "eml") {
			continue;
		}
		let bytes = std::fs::read(&path).expect("read");
		if crypto.decode(&bytes).expect("decode") == body {
			std::fs::remove_file(&path).expect("remove");
			return;
		}
	}
	panic!("no local message with that body");
}

#[tokio::test]
async fn a_message_the_user_deleted_is_not_stored_again_after_a_cut() {
	let server = FakeServer::start(
		Mode::Tls,
		'.',
		inbox(vec![
			Message::new(1, "", DATE_1, &mail("1", "one")),
			Message::new(2, "", DATE_2, &mail("2", "two")),
		]),
	)
	.await;
	let dir = tempfile::tempdir().expect("tempdir");
	let (first, error) = migrate(&server, dir.path(), &settings()).await;
	assert!(error.is_none(), "{error:?}");
	assert_eq!(first.copied, 2);
	assert_eq!(local(dir.path(), "INBOX").len(), 2);

	// The user deletes one of the two copies, and a later run is cut before
	// the checkpoint that would confirm its batch.
	remove_local(dir.path(), &mail("1", "one"));
	replay_from_the_start(dir.path());

	let (second, error) = migrate(&server, dir.path(), &settings()).await;
	assert!(error.is_none(), "{error:?}");
	assert_eq!(second.folders[0].copied, 0, "nothing is fetched again");
	assert_eq!(
		second.folders[0].confirmed, 2,
		"the ledger confirms both messages instead of downloading them"
	);
	assert_eq!(
		local(dir.path(), "INBOX").len(),
		1,
		"the deleted message is not resurrected"
	);
}

#[tokio::test]
async fn two_identical_messages_stay_two_across_a_replay() {
	let pair = mail("dup", "same");
	let server = FakeServer::start(
		Mode::Tls,
		'.',
		inbox(vec![
			Message::new(1, "", DATE_1, &pair),
			Message::new(2, "", DATE_2, &pair),
			Message::new(3, "", DATE_1, &mail("3", "three")),
		]),
	)
	.await;
	let dir = tempfile::tempdir().expect("tempdir");
	let (first, error) = migrate(&server, dir.path(), &settings()).await;
	assert!(error.is_none(), "{error:?}");
	assert_eq!(first.copied, 3);

	replay_from_the_start(dir.path());
	let (second, error) = migrate(&server, dir.path(), &settings()).await;
	assert!(error.is_none(), "{error:?}");
	assert_eq!(second.folders[0].copied, 0);
	assert_eq!(
		local(dir.path(), "INBOX").len(),
		3,
		"skipping a confirmed message consumes its identity, so the identical pair is not collapsed into one"
	);

	// Removing one copy of the pair leaves the other one, and the ledger does
	// not bring either back.
	remove_local(dir.path(), &pair);
	replay_from_the_start(dir.path());
	let (third, error) = migrate(&server, dir.path(), &settings()).await;
	assert!(error.is_none(), "{error:?}");
	assert_eq!(third.folders[0].copied, 0);
	assert_eq!(
		local(dir.path(), "INBOX").len(),
		2,
		"the copy the user kept is the one that stays"
	);
}

#[tokio::test]
async fn a_copy_that_arrives_after_its_twin_was_confirmed_is_stored_again() {
	let pair = mail("dup", "same");
	let mut all = inbox(vec![Message::new(1, "", DATE_1, &pair)]);
	let server = FakeServer::start(Mode::Tls, '.', all.clone()).await;
	let dir = tempfile::tempdir().expect("tempdir");
	let (first, error) = migrate(&server, dir.path(), &settings()).await;
	assert!(error.is_none(), "{error:?}");
	assert_eq!(first.copied, 1);

	// The source receives the same message a second time, and the next run is
	// cut before the batch that carries it is confirmed.
	all[0].messages.push(Message::new(2, "", DATE_2, &pair));
	server.edit(|folders| folders[0].messages = all[0].messages.clone());
	replay_from_the_start(dir.path());

	let (second, error) = migrate(&server, dir.path(), &settings()).await;
	assert!(error.is_none(), "{error:?}");
	assert_eq!(second.folders[0].confirmed, 1, "the first copy is skipped");
	assert_eq!(
		(second.folders[0].copied, second.folders[0].duplicates),
		(1, 0),
		"the confirmed copy consumed its identity, so the new twin is not taken for a duplicate"
	);
	assert_eq!(
		local(dir.path(), "INBOX").len(),
		2,
		"two identical messages in the source are two messages here"
	);
}

#[tokio::test]
async fn a_changed_uidvalidity_discards_the_ledger_and_copies_the_folder_again() {
	let mut all = inbox(vec![
		Message::new(1, "", DATE_1, &mail("1", "one")),
		Message::new(2, "", DATE_2, &mail("2", "two")),
	]);
	let server = FakeServer::start(Mode::Tls, '.', all.clone()).await;
	let dir = tempfile::tempdir().expect("tempdir");
	migrate(&server, dir.path(), &settings()).await;
	let first = states(dir.path());
	let path = first.ledger_path(b"INBOX").expect("path");
	assert!(
		path.exists(),
		"the folder keeps a ledger of what it confirmed"
	);
	let ledger = first
		.ledger(b"INBOX", all[0].uid_validity, false)
		.expect("open");
	assert_eq!((ledger.count(), ledger.last_uid()), (2, 2));

	// The source renumbers the folder and the messages behind the new numbers
	// are not the ones behind the old ones. The ledger says nothing about them,
	// so it is discarded and the folder is read again from the start.
	all[0].uid_validity += 1;
	all[0].messages = vec![
		Message::new(1, "", DATE_1, &mail("4", "four")),
		Message::new(2, "", DATE_2, &mail("5", "five")),
	];
	server.edit(|folders| {
		folders[0].uid_validity = all[0].uid_validity;
		folders[0].messages = all[0].messages.clone();
	});
	let (summary, error) = migrate(&server, dir.path(), &settings()).await;
	assert!(error.is_none(), "{error:?}");
	let folder = &summary.folders[0];
	assert!(folder.restarted, "a new UIDVALIDITY starts a new migration");
	assert_eq!(
		(folder.copied, folder.duplicates, folder.confirmed),
		(2, 0, 0),
		"the folder is read again from its first UID, and UIDs 1 and 2 under the new UIDVALIDITY are messages of their own"
	);
	assert_eq!(local(dir.path(), "INBOX").len(), 4);
	let ledger = states(dir.path())
		.ledger(b"INBOX", all[0].uid_validity, false)
		.expect("open");
	assert_eq!(
		(ledger.uid_validity(), ledger.last_uid()),
		(all[0].uid_validity, 2),
		"the ledger belongs to the new UIDVALIDITY"
	);

	// The folder is renumbered once more and nothing of it is carried over, so
	// the run confirms nothing. The ledger it leaves behind is still one the next
	// run can read.
	all[0].uid_validity += 1;
	all[0].messages = vec![Message::new(1, "\\Deleted", DATE_1, &mail("7", "seven"))];
	server.edit(|folders| {
		folders[0].uid_validity = all[0].uid_validity;
		folders[0].messages = all[0].messages.clone();
	});
	let (third, error) = migrate(&server, dir.path(), &settings()).await;
	assert!(error.is_none(), "{error:?}");
	assert_eq!(third.folders[0].deleted, 1, "nothing is confirmed");

	all[0].messages = vec![
		Message::new(1, "\\Deleted", DATE_1, &mail("7", "seven")),
		Message::new(2, "", DATE_2, &mail("6", "six")),
	];
	server.edit(|folders| folders[0].messages = all[0].messages.clone());
	replay_from_the_start(dir.path());
	let (fourth, error) = migrate(&server, dir.path(), &settings()).await;
	assert!(error.is_none(), "{error:?}");
	assert_eq!(fourth.folders[0].copied, 1);
	assert_eq!(local(dir.path(), "INBOX").len(), 5);
}

#[tokio::test]
async fn a_cut_before_the_ledger_sync_leaves_the_batch_unconfirmed() {
	let server = FakeServer::start(
		Mode::Tls,
		'.',
		inbox(vec![
			Message::new(1, "", DATE_1, &mail("1", "one")),
			Message::new(2, "", DATE_2, &mail("2", "two")),
		]),
	)
	.await;
	let dir = tempfile::tempdir().expect("tempdir");
	let guard = super::durability::tests::begin(Some("ledger-file"));
	let (_, error) = migrate(&server, dir.path(), &settings()).await;
	assert!(
		matches!(error, Some(MigrateError::State(_))),
		"refuse to confirm a batch whose ledger did not reach the disk: {error:?}"
	);
	let states = states(dir.path());
	let saved = states.load(b"INBOX").expect("load").expect("saved");
	assert_eq!(
		saved.last_uid, 0,
		"the batch is not confirmed by the checkpoint"
	);
	assert!(saved.in_progress, "the folder is replayed");
	drop(guard);

	let (_, error) = migrate(&server, dir.path(), &settings()).await;
	assert!(error.is_none(), "{error:?}");
	assert_eq!(
		local(dir.path(), "INBOX").len(),
		2,
		"each message is stored once"
	);
}

#[tokio::test]
async fn a_corrupt_ledger_stops_the_folder_and_says_how_to_start_over() {
	let server = FakeServer::start(
		Mode::Tls,
		'.',
		inbox(vec![
			Message::new(1, "", DATE_1, &mail("1", "one")),
			Message::new(2, "", DATE_2, &mail("2", "two")),
		]),
	)
	.await;
	let dir = tempfile::tempdir().expect("tempdir");
	migrate(&server, dir.path(), &settings()).await;
	let path = states(dir.path()).ledger_path(b"INBOX").expect("path");
	std::fs::write(&path, b"not a ledger at all").expect("corrupt");

	let (_, error) = migrate(&server, dir.path(), &settings()).await;
	let message = error.expect("the folder stops").to_string();
	assert!(
		message.contains("migration ledger")
			&& message.contains(&path.display().to_string())
			&& message.contains("delete that file"),
		"a corrupt ledger says what to do: {message}"
	);
	assert_eq!(
		local(dir.path(), "INBOX").len(),
		2,
		"nothing is imported and nothing is removed"
	);
}

#[tokio::test]
async fn a_dry_run_changes_nothing_of_the_ledger_or_of_the_progress() {
	let mut all = inbox(vec![
		Message::new(1, "", DATE_1, &mail("1", "one")),
		Message::new(2, "", DATE_2, &mail("2", "two")),
	]);
	let server = FakeServer::start(Mode::Tls, '.', all.clone()).await;
	let dir = tempfile::tempdir().expect("tempdir");
	migrate(&server, dir.path(), &settings()).await;
	replay_from_the_start(dir.path());
	let ledger = states(dir.path()).ledger_path(b"INBOX").expect("path");
	let before = std::fs::read(&ledger).expect("read");
	let saved = states(dir.path())
		.load(b"INBOX")
		.expect("load")
		.expect("saved");

	// The source renumbers the folder, which is the one thing that would make a
	// run rewrite its ledger even while it copies nothing.
	all[0].uid_validity += 1;
	server.edit(|folders| folders[0].uid_validity = all[0].uid_validity);

	let mut settings = settings();
	settings.dry_run = true;
	let (summary, error) = migrate(&server, dir.path(), &settings).await;
	assert!(error.is_none(), "{error:?}");
	assert_eq!(summary.copied, 0);
	assert_eq!(
		std::fs::read(&ledger).expect("read"),
		before,
		"a dry run neither appends to the ledger nor discards it"
	);
	assert_eq!(
		states(dir.path()).load(b"INBOX").expect("load"),
		Some(saved.clone()),
		"a dry run saves no checkpoint of its own"
	);
	assert!(saved.in_progress, "the folder is still replayed");
}

#[tokio::test]
async fn a_source_without_uidvalidity_still_migrates_and_keeps_no_ledger() {
	let mut all = inbox(vec![
		Message::new(1, "", DATE_1, &mail("1", "one")),
		Message::new(2, "", DATE_2, &mail("2", "two")),
	]);
	all[0].uid_validity = 0;
	let server = FakeServer::start(Mode::Tls, '.', all).await;
	let dir = tempfile::tempdir().expect("tempdir");

	let (first, error) = migrate(&server, dir.path(), &settings()).await;
	assert!(error.is_none(), "{error:?}");
	assert_eq!(first.copied, 2);
	assert_eq!(first.folders[0].confirmed, 0);
	assert_eq!(local(dir.path(), "INBOX").len(), 2);
	assert!(
		!states(dir.path())
			.ledger_path(b"INBOX")
			.expect("path")
			.exists(),
		"UIDs without a UIDVALIDITY name nothing worth keeping"
	);

	// A rerun matches against the mailbox instead, as it always did.
	let (second, error) = migrate(&server, dir.path(), &settings()).await;
	assert!(error.is_none(), "{error:?}");
	assert_eq!(second.copied, 0);
	assert_eq!(second.folders[0].duplicates, 2);
	assert_eq!(
		local(dir.path(), "INBOX").len(),
		2,
		"nothing is stored twice"
	);
}
