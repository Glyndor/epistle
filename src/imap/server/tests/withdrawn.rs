//! A session that signed in before its account was disabled, or before its
//! credentials were reset, ends at its next command, or at the next poll of
//! an IDLE, with an untagged `BYE`. Another account's change leaves it alone.

use super::base::read_until;
use super::*;
use crate::test_support::{accounts, fixtures};

use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

const WITHDRAWN: &str = "* BYE account no longer available";

/// A store holding `alice` and `bob`, and a message in alice's inbox.
fn store(dir: &std::path::Path) -> crate::directory_store::AccountStore {
	let store = accounts::store(dir, &["alice", "bob"]);
	let inbox = dir.join("accounts/alice/new");
	std::fs::create_dir_all(&inbox).expect("dirs");
	std::fs::write(
		inbox.join(format!("{}.eml", uuid::Uuid::now_v7())),
		b"From: b@x.example\r\nSubject: hi\r\n\r\nhello\r\n",
	)
	.expect("write");
	store
}

/// A server on the store's directory handle, and alice signed in to it with
/// INBOX selected.
async fn signed_in(
	dir: &std::path::Path,
	store: &crate::directory_store::AccountStore,
) -> (
	TlsStream<tokio::io::DuplexStream>,
	tokio::task::JoinHandle<std::io::Result<()>>,
) {
	let (acceptor, cert) = crate::tls::test_support::acceptor_and_cert();
	let server = Server::new(
		"mail.example.org",
		dir.to_path_buf(),
		store.handle(),
		acceptor,
		TlsMode::Implicit,
	);
	let (client, server_stream) = tokio::io::duplex(64 * 1024);
	let task = tokio::spawn(async move { server.handle(server_stream, None).await });
	let mut roots = RootCertStore::empty();
	roots.add(cert).expect("trust cert");
	crate::tls::ensure_crypto_provider();
	let config = ClientConfig::builder()
		.with_root_certificates(roots)
		.with_no_client_auth();
	let name = ServerName::try_from("mail.example.org").expect("name");
	let mut tls = TlsConnector::from(Arc::new(config))
		.connect(name, client)
		.await
		.expect("handshake");
	read_until(&mut tls, "IMAP4rev2 ready").await;
	tls.write_all(format!("a1 LOGIN alice {}\r\n", fixtures::password()).as_bytes())
		.await
		.expect("login");
	read_until(&mut tls, "a1 OK").await;
	tls.write_all(b"a2 SELECT INBOX\r\n").await.expect("select");
	let select = read_until(&mut tls, "a2 OK").await;
	assert!(select.contains("* 1 EXISTS"), "{select}");
	(tls, task)
}

/// Everything the server sends until it closes the connection.
async fn rest(tls: &mut TlsStream<tokio::io::DuplexStream>) -> String {
	let mut seen = String::new();
	let mut chunk = [0u8; 4096];
	while let Ok(read) = tls.read(&mut chunk).await
		&& read > 0
	{
		seen.push_str(&String::from_utf8_lossy(&chunk[..read]));
	}
	seen
}

/// The reply to a FETCH of the one message: up to its tagged line, or up to
/// the `BYE` that ends the session instead.
async fn fetch(tls: &mut TlsStream<tokio::io::DuplexStream>) -> String {
	tls.write_all(b"a3 FETCH 1 (BODY[])\r\n")
		.await
		.expect("fetch");
	let mut seen = String::new();
	let mut chunk = [0u8; 4096];
	while !seen.contains("a3 ") && !seen.contains("* BYE") {
		let read = tls.read(&mut chunk).await.expect("read");
		assert!(read > 0, "closed without a reply: {seen}");
		seen.push_str(&String::from_utf8_lossy(&chunk[..read]));
	}
	seen
}

#[tokio::test]
async fn a_command_after_the_account_is_disabled_gets_bye() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = store(dir.path());
	let (mut tls, task) = signed_in(dir.path(), &store).await;
	accounts::disable(&store, "alice");
	let reply = fetch(&mut tls).await;
	assert!(reply.contains(WITHDRAWN), "{reply}");
	assert!(!reply.contains("Subject: hi"), "{reply}");
	assert_eq!(rest(&mut tls).await, "");
	assert!(task.await.expect("join").is_ok());
}

#[tokio::test]
async fn a_command_after_a_credential_reset_gets_bye() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = store(dir.path());
	let (mut tls, task) = signed_in(dir.path(), &store).await;
	accounts::reset(&store, "alice");
	let reply = fetch(&mut tls).await;
	assert!(reply.contains(WITHDRAWN), "{reply}");
	assert!(!reply.contains("Subject: hi"), "{reply}");
	assert_eq!(rest(&mut tls).await, "");
	assert!(task.await.expect("join").is_ok());
}

#[tokio::test]
async fn disabling_another_account_leaves_the_session_alone() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = store(dir.path());
	let (mut tls, task) = signed_in(dir.path(), &store).await;
	accounts::disable(&store, "bob");
	let reply = fetch(&mut tls).await;
	assert!(reply.contains("Subject: hi"), "{reply}");
	assert!(reply.contains("a3 OK"), "{reply}");
	task.abort();
}

#[tokio::test(start_paused = true)]
async fn an_idle_session_ends_at_the_next_poll() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = store(dir.path());
	let (mut tls, task) = signed_in(dir.path(), &store).await;
	tls.write_all(b"a3 IDLE\r\n").await.expect("idle");
	read_until(&mut tls, "+ ").await;
	accounts::disable(&store, "alice");
	// The paused clock jumps to the next poll; without the check the IDLE
	// would run until its own timeout and close with a different BYE.
	let seen = rest(&mut tls).await;
	assert!(seen.contains(WITHDRAWN), "{seen}");
	assert!(!seen.contains("idle timeout"), "{seen}");
	assert!(task.await.expect("join").is_ok());
}

#[tokio::test(start_paused = true)]
async fn a_notify_session_ends_at_the_next_poll() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = store(dir.path());
	let (mut tls, task) = signed_in(dir.path(), &store).await;
	tls.write_all(b"a3 NOTIFY SET (selected (MessageNew MessageExpunge))\r\n")
		.await
		.expect("notify");
	read_until(&mut tls, "a3 OK").await;
	accounts::disable(&store, "alice");
	let seen = rest(&mut tls).await;
	assert!(seen.contains(WITHDRAWN), "{seen}");
	assert!(!seen.contains("idle timeout"), "{seen}");
	assert!(task.await.expect("join").is_ok());
}
