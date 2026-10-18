//! What COPY and MOVE teach the account corpus when Junk is on either end.
//!
//! The session is wired to a queue whose receiver the test holds, so each
//! test reads the lessons the command queued and nothing else.

use super::*;
use crate::antispam::training_queue::{
	MAX_JOBS_PER_COMMAND, MAX_PENDING_PER_ACCOUNT, TrainingJob, TrainingQueue,
};
use crate::metrics::Metrics;
use tokio::sync::mpsc::Receiver;

fn learning_session(dir: &std::path::Path) -> (Session, Receiver<TrainingJob>, Arc<Metrics>) {
	learning_session_with(dir, MAX_JOBS_PER_COMMAND)
}

/// A session whose commands may teach `lessons` messages each.
fn learning_session_with(
	dir: &std::path::Path,
	lessons: usize,
) -> (Session, Receiver<TrainingJob>, Arc<Metrics>) {
	let metrics = Arc::new(Metrics::new());
	let (queue, receiver) = TrainingQueue::bounded(512, Arc::clone(&metrics));
	let queue = queue.with_command_lessons(lessons);
	let mut session = Session::new("mail.example.org", dir.to_path_buf(), directory());
	session = session.with_training(queue);
	let output = session.command_line(&format!("a1 LOGIN alice {}", fixtures::password()));
	assert!(text(&output).contains("a1 OK"), "login must succeed");
	(session, receiver, metrics)
}

fn lessons(receiver: &mut Receiver<TrainingJob>) -> Vec<TrainingJob> {
	let mut out = Vec::new();
	while let Ok(job) = receiver.try_recv() {
		out.push(job);
	}
	out
}

fn put(dir: &std::path::Path, mailbox: &str, body: &[u8]) {
	crate::imap::mailbox::append(
		dir,
		"alice",
		mailbox,
		&[],
		body,
		&crate::storage::MessageCrypto::disabled(),
	)
	.expect("seed message");
}

fn dir_of(dir: &std::path::Path, mailbox: &str) -> std::path::PathBuf {
	crate::imap::mailbox::mailbox_dir(dir, "alice", mailbox).expect("mailbox dir")
}

#[test]
fn copy_into_junk_teaches_spam_from_the_stored_copy() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"Subject: offer\r\n\r\nbuy now\r\n");
	let (mut session, mut receiver, _) = learning_session(dir.path());
	session.command_line("a2 CREATE Junk");
	session.command_line("a3 SELECT INBOX");
	let response = text(&session.command_line("a4 COPY 1 Junk"));
	assert!(response.contains("a4 OK"), "{response}");
	let jobs = lessons(&mut receiver);
	assert_eq!(jobs.len(), 1, "one lesson for one message");
	assert!(jobs[0].spam, "a message copied into Junk is spam");
	assert_eq!(jobs[0].account, "alice");
	assert_eq!(
		jobs[0].path.parent(),
		Some(dir_of(dir.path(), "Junk").as_path()),
		"the lesson names the copy stored in Junk"
	);
	assert!(jobs[0].path.is_file(), "the stored copy exists");
}

#[test]
fn move_into_junk_teaches_spam_and_the_lesson_outlives_the_source() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"Subject: offer\r\n\r\nbuy now\r\n");
	let (mut session, mut receiver, _) = learning_session(dir.path());
	session.command_line("a2 CREATE Junk");
	session.command_line("a3 SELECT INBOX");
	let response = text(&session.command_line("a4 MOVE 1 Junk"));
	assert!(response.contains("a4 OK"), "{response}");
	let jobs = lessons(&mut receiver);
	assert_eq!(jobs.len(), 1);
	assert!(jobs[0].spam);
	assert!(
		jobs[0].path.is_file(),
		"the file the lesson names is the one that survives the move"
	);
}

#[test]
fn move_out_of_junk_teaches_ham() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts/alice/new")).expect("account");
	put(dir.path(), "Junk", b"Subject: lunch\r\n\r\nnoon?\r\n");
	let (mut session, mut receiver, _) = learning_session(dir.path());
	session.command_line("a2 SELECT Junk");
	let response = text(&session.command_line("a3 MOVE 1 INBOX"));
	assert!(response.contains("a3 OK"), "{response}");
	let jobs = lessons(&mut receiver);
	assert_eq!(jobs.len(), 1);
	assert!(!jobs[0].spam, "a message moved out of Junk is ham");
	assert_eq!(
		jobs[0].path.parent(),
		Some(dir_of(dir.path(), "INBOX").as_path())
	);
}

#[test]
fn what_the_user_does_not_vouch_for_teaches_nothing() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts/alice/new")).expect("account");
	put(dir.path(), "Junk", b"one\r\n");
	put(dir.path(), "Junk", b"two\r\n");
	put(dir.path(), "INBOX", b"three\r\n");
	let (mut session, mut receiver, _) = learning_session(dir.path());
	session.command_line("a2 CREATE Trash");
	session.command_line("a3 CREATE Archive");
	session.command_line("a4 CREATE Archive/Junk");
	session.command_line("a5 SELECT Junk");
	assert!(text(&session.command_line("a6 MOVE 1 Trash")).contains("a6 OK"));
	assert!(text(&session.command_line("a7 COPY 1 INBOX")).contains("a7 OK"));
	session.command_line("a8 SELECT INBOX");
	assert!(text(&session.command_line("a9 MOVE 1 Archive")).contains("a9 OK"));
	assert!(text(&session.command_line("a10 COPY 1 Archive/Junk")).contains("a10 OK"));
	assert!(
		lessons(&mut receiver).is_empty(),
		"Junk to Trash, a copy out of Junk, an ordinary move and a folder that only ends in Junk teach nothing"
	);
}

#[test]
fn a_message_that_claims_to_be_spam_teaches_nothing_by_itself() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(
		dir.path(),
		b"X-Spam-Flag: YES\r\nX-Epistle-Learn: spam\r\nSubject: hi\r\n\r\nbody\r\n",
	);
	let (mut session, mut receiver, _) = learning_session(dir.path());
	session.command_line("a2 CREATE Archive");
	session.command_line("a3 SELECT INBOX");
	assert!(text(&session.command_line("a4 MOVE 1 Archive")).contains("a4 OK"));
	let response = text(&session.command_line("a5 COPY 1 \"junk/..\""));
	assert!(response.contains("a5 NO"), "{response}");
	assert!(
		lessons(&mut receiver).is_empty(),
		"neither a header nor an invented mailbox name teaches anything"
	);
}

#[test]
fn a_move_of_a_whole_junk_folder_queues_a_bounded_batch() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts/alice/new")).expect("account");
	let total = MAX_JOBS_PER_COMMAND + 50;
	for n in 0..total {
		put(
			dir.path(),
			"Junk",
			format!("Subject: {n}\r\n\r\nbody\r\n").as_bytes(),
		);
	}
	let (mut session, mut receiver, metrics) = learning_session(dir.path());
	session.command_line("a2 SELECT Junk");
	let response = text(&session.command_line("a3 MOVE 1:* INBOX"));
	assert!(response.contains("a3 OK"), "{response}");
	assert_eq!(
		lessons(&mut receiver).len(),
		MAX_PENDING_PER_ACCOUNT,
		"one account has at most its share of the queue waiting"
	);
	let dropped = u64::try_from(total - MAX_PENDING_PER_ACCOUNT).expect("fits");
	assert_eq!(
		metrics.snapshot().get("bayes_training_dropped").copied(),
		Some(dropped),
		"every message that did not get a place is counted as dropped"
	);
	let moved = text(&session.command_line("a4 SELECT INBOX"));
	assert!(
		moved.contains(&format!("* {total} EXISTS")),
		"every message still moved: {moved}"
	);
}

#[test]
fn a_copy_into_junk_teaches_at_most_its_commands_budget() {
	let dir = tempfile::tempdir().expect("tempdir");
	for n in 0..10 {
		deliver(
			dir.path(),
			format!("Subject: {n}\r\n\r\nbody\r\n").as_bytes(),
		);
	}
	let (mut session, mut receiver, metrics) = learning_session_with(dir.path(), 3);
	session.command_line("a2 CREATE Junk");
	session.command_line("a3 SELECT INBOX");
	assert!(text(&session.command_line("a4 COPY 1:* Junk")).contains("a4 OK"));
	assert_eq!(lessons(&mut receiver).len(), 3, "the command's budget");
	assert_eq!(
		metrics.snapshot().get("bayes_training_dropped").copied(),
		Some(7)
	);
}

#[test]
fn a_store_of_junk_on_many_messages_teaches_at_most_its_commands_budget() {
	let dir = tempfile::tempdir().expect("tempdir");
	for n in 0..10 {
		deliver(
			dir.path(),
			format!("Subject: {n}\r\n\r\nbody\r\n").as_bytes(),
		);
	}
	let (mut session, mut receiver, metrics) = learning_session_with(dir.path(), 3);
	session.command_line("a2 SELECT INBOX");
	assert!(text(&session.command_line("a3 STORE 1:* +FLAGS ($Junk)")).contains("a3 OK"));
	assert_eq!(lessons(&mut receiver).len(), 3, "the command's budget");
	assert_eq!(
		metrics.snapshot().get("bayes_training_dropped").copied(),
		Some(7)
	);
}
