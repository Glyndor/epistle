//! What a rerun of a migration does with what the ledger already confirmed: a
//! batch that stopped half way, a source that stops marking a message deleted,
//! a message confirmed below what the ledger reaches, a migration a version
//! without a ledger started, and a second run that starts while the first still
//! holds the account.

use std::time::Duration;

use super::fake_server::{FakeServer, Fault, Message, Mode};
use super::ledger_resume_tests::{inbox, remove_local, replay_from_the_start, states};
use super::run_tests::{DATE_1, DATE_2, Quiet, local, mail, migrate, settings, source, target};
use super::{MigrateError, Security, run};

/// Three messages in INBOX, none of them marked for deletion.
fn three() -> Vec<super::fake_server::Folder> {
	inbox(vec![
		Message::new(1, "", DATE_1, &mail("1", "one")),
		Message::new(2, "", DATE_2, &mail("2", "two")),
		Message::new(3, "", DATE_1, &mail("3", "three")),
	])
}

/// How many messages the local INBOX holds, counted from its files: a message
/// removed with `remove_local` leaves no modseq behind, so a cached index
/// stamped before it can still name it.
fn stored(dir: &std::path::Path) -> usize {
	let mailbox = crate::imap::mailbox::mailbox_dir(dir, "alice", "INBOX").expect("mailbox");
	std::fs::read_dir(mailbox)
		.expect("entries")
		.filter(|entry| {
			entry
				.as_ref()
				.expect("entry")
				.path()
				.extension()
				.is_some_and(|extension| extension == "eml")
		})
		.count()
}

#[tokio::test]
async fn a_quota_stop_in_the_middle_of_a_batch_confirms_what_that_batch_stored() {
	let all = three();
	let uid_validity = all[0].uid_validity;
	let server = FakeServer::start(Mode::Tls, '.', all).await;
	let dir = tempfile::tempdir().expect("tempdir");

	// Room for the first message of the batch only.
	let mut limited = target(dir.path());
	limited.quota = Some(mail("1", "one").len() as u64);
	let (first, error) = run(
		&source(&server, Security::Tls),
		&mut limited,
		&settings(),
		&mut Quiet::default(),
	)
	.await;
	assert!(
		matches!(error, Some(MigrateError::Quota { .. })),
		"{error:?}"
	);
	assert_eq!(first.folders[0].copied, 1, "one message fit");

	// It is in the local mailbox, so the ledger records it even though the
	// batch it belonged to never finished.
	let mut ledger = states(dir.path())
		.ledger(b"INBOX", uid_validity, false)
		.expect("ledger");
	assert!(
		ledger.fingerprint(1).expect("fingerprint").is_some(),
		"the message that fit is confirmed, so the run that continues does not download it again"
	);
	drop(ledger);

	// The quota is raised and the run is cut before the checkpoint that would
	// confirm the next batch, so the folder is replayed from its first UID.
	replay_from_the_start(dir.path());
	let (second, error) = migrate(&server, dir.path(), &settings()).await;
	assert!(error.is_none(), "{error:?}");
	assert_eq!(
		(second.folders[0].copied, second.folders[0].confirmed),
		(2, 1),
		"the confirmed message is skipped and the rest arrives"
	);
	assert_eq!(
		local(dir.path(), "INBOX").len(),
		3,
		"each message is stored once"
	);
}

#[tokio::test]
async fn a_message_the_source_stops_marking_deleted_is_copied_after_a_replay() {
	let mut all = inbox(vec![
		Message::new(1, "\\Deleted", DATE_1, &mail("1", "one")),
		Message::new(2, "", DATE_2, &mail("2", "two")),
	]);
	let server = FakeServer::start(Mode::Tls, '.', all.clone()).await;
	let dir = tempfile::tempdir().expect("tempdir");
	let (first, error) = migrate(&server, dir.path(), &settings()).await;
	assert!(error.is_none(), "{error:?}");
	assert_eq!((first.folders[0].deleted, first.folders[0].copied), (1, 1));

	// The user clears the flag at the source and a later run is cut before the
	// checkpoint that would confirm its batch. UID 1 is then confirmed below
	// what UID 2 reached, which the ledger leaves out instead of refusing, so
	// the folder can finish.
	all[0].messages[0] = Message::new(1, "", DATE_1, &mail("1", "one"));
	server.edit(|folders| folders[0].messages = all[0].messages.clone());
	replay_from_the_start(dir.path());

	let (second, error) = migrate(&server, dir.path(), &settings()).await;
	assert!(error.is_none(), "the folder finishes: {error:?}");
	assert_eq!(
		(second.folders[0].copied, second.folders[0].confirmed),
		(1, 1),
		"UID 1 is copied and UID 2 stays confirmed"
	);
	assert_eq!(local(dir.path(), "INBOX").len(), 2);

	// The record left out of the ledger is matched against the local mailbox on
	// the next replay, so nothing is stored twice.
	replay_from_the_start(dir.path());
	let (third, error) = migrate(&server, dir.path(), &settings()).await;
	assert!(error.is_none(), "{error:?}");
	assert_eq!(
		(third.folders[0].copied, third.folders[0].duplicates),
		(0, 1),
		"the message that is already here is not stored again"
	);
	assert_eq!(local(dir.path(), "INBOX").len(), 2);
}

/// The cost of a message confirmed below the UID the ledger already reaches: it
/// has no record of its own, because the records only rise in UID order, so it
/// is matched against the local mailbox on every replay from then on and
/// deleting the copy locally brings it back.
#[tokio::test]
async fn a_message_confirmed_below_what_the_ledger_reaches_comes_back_after_a_local_deletion() {
	let mut all = inbox(vec![
		Message::new(1, "\\Deleted", DATE_1, &mail("1", "one")),
		Message::new(2, "", DATE_2, &mail("2", "two")),
	]);
	let server = FakeServer::start(Mode::Tls, '.', all.clone()).await;
	let dir = tempfile::tempdir().expect("tempdir");
	let (first, error) = migrate(&server, dir.path(), &settings()).await;
	assert!(error.is_none(), "{error:?}");
	assert_eq!((first.folders[0].deleted, first.folders[0].copied), (1, 1));

	// The user clears the flag at the source and the folder is replayed, so
	// UID 1 is stored below the UID the ledger already reaches. Its record is
	// left out, as `a_message_the_source_stops_marking_deleted_is_copied_after_a_replay`
	// shows, and from then on it is matched against the mailbox.
	all[0].messages[0] = Message::new(1, "", DATE_1, &mail("1", "one"));
	server.edit(|folders| folders[0].messages = all[0].messages.clone());
	replay_from_the_start(dir.path());
	let (second, error) = migrate(&server, dir.path(), &settings()).await;
	assert!(error.is_none(), "the folder finishes: {error:?}");
	assert_eq!(second.folders[0].copied, 1, "UID 1 is stored");
	assert_eq!(stored(dir.path()), 2);

	// The user deletes that copy, and the folder is replayed once more. The
	// ledger holds nothing for UID 1, so the message is downloaded again.
	remove_local(dir.path(), &mail("1", "one"));
	replay_from_the_start(dir.path());
	let (third, error) = migrate(&server, dir.path(), &settings()).await;
	assert!(error.is_none(), "{error:?}");
	assert_eq!(
		(
			third.folders[0].copied,
			third.folders[0].duplicates,
			third.folders[0].confirmed
		),
		(1, 0, 1),
		"UID 1 is downloaded again and only UID 2 is confirmed by the ledger"
	);
	assert_eq!(stored(dir.path()), 2);
}

#[tokio::test]
async fn a_migration_a_version_without_a_ledger_started_resumes_with_the_new_one() {
	let all = three();
	let server = FakeServer::start(Mode::Tls, '.', all).await;
	let dir = tempfile::tempdir().expect("tempdir");
	// Batches of two, so the first batch is confirmed and the second is cut
	// before any of its bodies arrive.
	server.set_fault(Fault::DropDuringFetch { fetch: 2, after: 0 });
	let (first, error) = migrate(&server, dir.path(), &settings()).await;
	assert!(error.is_some(), "the cut must stop the run");
	assert_eq!(first.folders[0].copied, 2);

	// What a version without a ledger leaves behind: the progress file of a
	// partial migration and no ledger at all.
	std::fs::remove_file(states(dir.path()).ledger_path(b"INBOX").expect("path")).expect("remove");
	let mut saved = states(dir.path())
		.load(b"INBOX")
		.expect("load")
		.expect("saved");
	saved.last_uid = 2;
	saved.in_progress = false;
	states(dir.path()).save(b"INBOX", &saved).expect("save");

	// The run carries on from the third UID, which the new ledger records.
	let (second, error) = migrate(&server, dir.path(), &settings()).await;
	assert!(error.is_none(), "{error:?}");
	assert_eq!(second.folders[0].copied, 1, "UID 3 arrives");

	// A cut after that leaves UIDs 1 and 2 below what the ledger reaches. The
	// folder still finishes instead of being stuck on them.
	replay_from_the_start(dir.path());
	let (third, error) = migrate(&server, dir.path(), &settings()).await;
	assert!(error.is_none(), "the folder finishes: {error:?}");
	assert_eq!(
		(third.folders[0].copied, third.folders[0].duplicates),
		(0, 2),
		"UIDs 1 and 2 are matched against the local mailbox, and UID 3 stays confirmed"
	);
	assert_eq!(third.folders[0].confirmed, 1);
	assert_eq!(
		local(dir.path(), "INBOX").len(),
		3,
		"each message is stored once"
	);
}

#[tokio::test]
async fn a_message_marked_deleted_is_not_confirmed_by_the_ledger() {
	let all = inbox(vec![
		Message::new(1, "\\Deleted", DATE_1, &mail("1", "one")),
		Message::new(2, "", DATE_2, &mail("2", "two")),
	]);
	let uid_validity = all[0].uid_validity;
	let server = FakeServer::start(Mode::Tls, '.', all).await;
	let dir = tempfile::tempdir().expect("tempdir");
	let (first, error) = migrate(&server, dir.path(), &settings()).await;
	assert!(error.is_none(), "{error:?}");
	assert_eq!((first.folders[0].deleted, first.folders[0].copied), (1, 1));
	assert_eq!(local(dir.path(), "INBOX").len(), 1);

	let mut ledger = states(dir.path())
		.ledger(b"INBOX", uid_validity, false)
		.expect("ledger");
	assert_eq!(
		(ledger.count(), ledger.last_uid()),
		(1, 2),
		"only the message that was stored is confirmed"
	);
	assert!(
		ledger.fingerprint(1).expect("fingerprint").is_none(),
		"a message that is not stored is not confirmed: a later run would skip it and it would never arrive"
	);
	drop(ledger);

	// The source clears the flag and the folder is replayed, so the message is
	// listed again.
	let all = inbox(vec![
		Message::new(1, "", DATE_1, &mail("1", "one")),
		Message::new(2, "", DATE_2, &mail("2", "two")),
	]);
	server.edit(|folders| folders[0].messages = all[0].messages.clone());
	replay_from_the_start(dir.path());
	let (second, error) = migrate(&server, dir.path(), &settings()).await;
	assert!(error.is_none(), "{error:?}");
	assert_eq!(
		(second.folders[0].copied, second.folders[0].confirmed),
		(1, 1),
		"the message is copied and the one already confirmed is not"
	);
	assert_eq!(local(dir.path(), "INBOX").len(), 2);
}

#[tokio::test]
async fn a_second_run_of_the_same_account_refuses_while_the_first_holds_the_lock() {
	let all = three();
	let server = FakeServer::start(Mode::Tls, '.', all).await;
	let dir = tempfile::tempdir().expect("tempdir");
	let first_run = states(dir.path())
		.lock(Duration::ZERO)
		.await
		.expect("the first run holds the lock");

	let mut impatient = settings();
	impatient.lock_wait = Duration::from_millis(200);
	let started = std::time::Instant::now();
	let (_, error) = migrate(&server, dir.path(), &impatient).await;
	let message = error.expect("the second run refuses").to_string();
	assert!(
		message.contains("another migration of the account alice")
			&& message.contains(".lock")
			&& message.contains("wait for it to finish"),
		"the refusal says who holds it and what to do: {message}"
	);
	assert!(
		started.elapsed() >= Duration::from_millis(200),
		"it waits for the deadline before it refuses"
	);
	drop(first_run);

	// With the lock free the run goes on and copies the folder.
	let (summary, error) = migrate(&server, dir.path(), &settings()).await;
	assert!(error.is_none(), "{error:?}");
	assert_eq!(summary.copied, 3);
	assert_eq!(local(dir.path(), "INBOX").len(), 3);
}

#[tokio::test]
async fn a_dry_run_takes_no_lock_and_waits_for_no_one() {
	let all = three();
	let server = FakeServer::start(Mode::Tls, '.', all).await;
	let dir = tempfile::tempdir().expect("tempdir");
	let first_run = states(dir.path())
		.lock(Duration::ZERO)
		.await
		.expect("another run holds the lock");

	let mut settings = settings();
	settings.dry_run = true;
	let (summary, error) = migrate(&server, dir.path(), &settings).await;
	assert!(
		error.is_none(),
		"a dry run writes nothing, so it waits for no one: {error:?}"
	);
	assert_eq!(summary.copied, 0);
	drop(first_run);
}
