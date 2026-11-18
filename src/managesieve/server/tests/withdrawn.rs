//! A signed-in session whose account was disabled, or had its credentials
//! reset, gets `BYE` and a close at its next command. Another account's
//! change leaves it alone.

use super::*;
use crate::directory_store::AccountStore;
use crate::test_support::accounts;
use tokio::io::DuplexStream;

const WITHDRAWN: &str = "BYE \"account no longer available\"\r\n";

/// The command loop over the store's directory handle, signed in as alice.
async fn signed_in(
	dir: &std::path::Path,
	store: &AccountStore,
) -> (DuplexStream, tokio::task::JoinHandle<std::io::Result<()>>) {
	std::fs::create_dir_all(dir.join("accounts/alice")).expect("dirs");
	let (acceptor, _cert) = crate::tls::test_support::acceptor_and_cert();
	let server = Server::new(dir.to_path_buf(), store.handle(), acceptor);
	let (mut client, server_stream) = tokio::io::duplex(64 * 1024);
	let task =
		tokio::spawn(async move { server.handle_preauth_for_test(server_stream, "alice").await });
	let mut greeting = String::new();
	while !greeting.ends_with("OK\r\n") && !greeting.contains("\r\nOK ") {
		greeting.push_str(&read_chunk(&mut client).await);
	}
	(client, task)
}

async fn read_chunk(client: &mut DuplexStream) -> String {
	let mut chunk = [0u8; 4096];
	let read = client.read(&mut chunk).await.expect("read");
	String::from_utf8_lossy(&chunk[..read]).to_string()
}

/// The reply to `command`, then whether the server closed after it.
async fn answer(client: &mut DuplexStream, command: &str) -> (String, bool) {
	client
		.write_all(format!("{command}\r\n").as_bytes())
		.await
		.expect("command");
	let first = read_chunk(client).await;
	let mut chunk = [0u8; 16];
	let closed = first == WITHDRAWN && client.read(&mut chunk).await.expect("read") == 0;
	(first, closed)
}

#[tokio::test]
async fn a_command_after_the_account_is_disabled_gets_bye() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = accounts::store(dir.path(), &["alice", "bob"]);
	let (mut client, task) = signed_in(dir.path(), &store).await;
	accounts::disable(&store, "alice");
	assert_eq!(
		answer(&mut client, "LISTSCRIPTS").await,
		(WITHDRAWN.to_string(), true)
	);
	assert!(task.await.expect("join").is_ok());
}

#[tokio::test]
async fn a_command_after_a_credential_reset_gets_bye() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = accounts::store(dir.path(), &["alice", "bob"]);
	let (mut client, task) = signed_in(dir.path(), &store).await;
	accounts::reset(&store, "alice");
	assert_eq!(
		answer(&mut client, "LISTSCRIPTS").await,
		(WITHDRAWN.to_string(), true)
	);
	assert!(task.await.expect("join").is_ok());
}

#[tokio::test]
async fn disabling_another_account_leaves_the_session_alone() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = accounts::store(dir.path(), &["alice", "bob"]);
	let (mut client, task) = signed_in(dir.path(), &store).await;
	accounts::disable(&store, "bob");
	let (listed, closed) = answer(&mut client, "LISTSCRIPTS").await;
	assert!(listed.starts_with("OK"), "{listed}");
	assert!(!closed);
	task.abort();
}
