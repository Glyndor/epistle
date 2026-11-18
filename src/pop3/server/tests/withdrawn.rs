//! A session that signed in before its account was disabled, or before its
//! credentials were reset, gets `-ERR` and a close at its next command, and
//! the deletions it marked are not committed. Another account's change
//! leaves it alone.

use super::*;
use crate::directory_store::AccountStore;
use crate::test_support::{accounts, fixtures};
use tokio::io::{DuplexStream, duplex};

const WITHDRAWN: &str = "-ERR account no longer available\r\n";

/// A store holding `alice` and `bob`, and one message in alice's inbox,
/// whose path is returned.
fn store(dir: &std::path::Path) -> (AccountStore, PathBuf) {
	let store = accounts::store(dir, &["alice", "bob"]);
	let inbox = dir.join("accounts/alice/new");
	std::fs::create_dir_all(&inbox).expect("dirs");
	let message = inbox.join(format!("{}.eml", uuid::Uuid::now_v7()));
	std::fs::write(
		&message,
		b"From: b@x.example\r\nSubject: hi\r\n\r\nhello\r\n",
	)
	.expect("write");
	(store, message)
}

async fn reply(client: &mut DuplexStream) -> String {
	let mut chunk = [0u8; 4096];
	let read = client.read(&mut chunk).await.expect("read");
	String::from_utf8_lossy(&chunk[..read]).to_string()
}

/// The protocol loop over the store's directory handle, with alice signed in.
async fn signed_in(
	dir: &std::path::Path,
	store: &AccountStore,
) -> (DuplexStream, tokio::task::JoinHandle<std::io::Result<()>>) {
	let backend = MailboxBackend::new(store.handle(), dir.to_path_buf());
	let clock = SessionClock::start(DEFAULT_PREAUTH_TIMEOUT, TIMEOUT);
	let (mut client, server) = duplex(64 * 1024);
	let task = tokio::spawn(async move { run(server, backend, None, clock, None).await });
	assert!(reply(&mut client).await.starts_with("+OK"));
	client.write_all(b"USER alice\r\n").await.expect("user");
	assert!(reply(&mut client).await.starts_with("+OK"));
	client
		.write_all(format!("PASS {}\r\n", fixtures::password()).as_bytes())
		.await
		.expect("pass");
	let signed = reply(&mut client).await;
	assert!(signed.starts_with("+OK"), "{signed}");
	(client, task)
}

/// The reply to `command`, then whether the server closed after it.
async fn answer(client: &mut DuplexStream, command: &str) -> (String, bool) {
	client
		.write_all(format!("{command}\r\n").as_bytes())
		.await
		.expect("command");
	let first = reply(client).await;
	let mut chunk = [0u8; 16];
	let closed = first == WITHDRAWN && client.read(&mut chunk).await.expect("read") == 0;
	(first, closed)
}

#[tokio::test]
async fn a_command_after_the_account_is_disabled_gets_err_and_a_close() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (store, _) = store(dir.path());
	let (mut client, task) = signed_in(dir.path(), &store).await;
	accounts::disable(&store, "alice");
	assert_eq!(
		answer(&mut client, "RETR 1").await,
		(WITHDRAWN.to_string(), true)
	);
	assert!(task.await.expect("join").is_ok());
}

#[tokio::test]
async fn a_command_after_a_credential_reset_gets_err_and_a_close() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (store, _) = store(dir.path());
	let (mut client, task) = signed_in(dir.path(), &store).await;
	accounts::reset(&store, "alice");
	assert_eq!(
		answer(&mut client, "STAT").await,
		(WITHDRAWN.to_string(), true)
	);
	assert!(task.await.expect("join").is_ok());
}

#[tokio::test]
async fn quit_after_the_account_is_disabled_commits_no_deletion() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (store, message) = store(dir.path());
	let (mut client, task) = signed_in(dir.path(), &store).await;
	client.write_all(b"DELE 1\r\n").await.expect("dele");
	assert!(reply(&mut client).await.starts_with("+OK"));
	accounts::disable(&store, "alice");
	assert_eq!(
		answer(&mut client, "QUIT").await,
		(WITHDRAWN.to_string(), true)
	);
	assert!(task.await.expect("join").is_ok());
	assert!(message.exists(), "the marked message was removed");
}

#[tokio::test]
async fn disabling_another_account_leaves_the_session_alone() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (store, _) = store(dir.path());
	let (mut client, task) = signed_in(dir.path(), &store).await;
	accounts::disable(&store, "bob");
	let (stat, closed) = answer(&mut client, "STAT").await;
	assert!(stat.starts_with("+OK 1 "), "{stat}");
	assert!(!closed);
	task.abort();
}
