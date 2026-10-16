//! The class of an authenticated SMTP submission comes from the credential
//! and the account, never from the message.

use std::sync::Mutex;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use tokio::io::AsyncWriteExt;

use super::tests_auth::{connector, directory_with_password, reply};
use super::*;
use crate::evidence::MailClass;
use crate::evidence::bindings::{BindingSet, app_password_key, update};
use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::{SinkError, Submission};

/// Keeps what was submitted and with which class.
#[derive(Default)]
struct ClassSink(
	Mutex<Vec<(AcceptedMessage, MailClass)>>,
	/// Answer every submission as a sink that cannot record its evidence.
	bool,
);

impl MessageSink for ClassSink {
	fn deliver(&self, message: AcceptedMessage) -> Result<(), SinkError> {
		self.0
			.lock()
			.expect("lock")
			.push((message, MailClass::Personal));
		Ok(())
	}

	fn submit(
		&self,
		message: AcceptedMessage,
		_: uuid::Uuid,
		_: &str,
		submission: &Submission,
	) -> Result<(), SinkError> {
		if self.1 {
			return Err(SinkError::EvidenceUnavailable("test".into()));
		}
		self.0
			.lock()
			.expect("lock")
			.push((message, submission.class));
		Ok(())
	}
}

fn app_password(label: &str, hash: &str) -> crate::directory_store::AppPassword {
	crate::directory_store::AppPassword {
		label: label.to_string(),
		hash: hash.to_string(),
		expires_at: None,
		ip_cidr: None,
		save_sent: None,
	}
}

fn message(headers: &str) -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: "alice@example.org".into(),
		recipients: vec!["bob@elsewhere.example".into()],
		data: format!("{headers}Subject: s\r\n\r\nbody\r\n").into_bytes(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: true,
		no_dsn: Vec::new(),
	}
}

#[test]
fn the_class_bound_to_the_app_password_applies_and_a_header_cannot_raise_it() {
	let dir = tempfile::tempdir().expect("tempdir");
	let hash = crate::smtp::auth::tests::hash(crate::smtp::auth::tests::fixture_password());
	update(dir.path(), |bindings| {
		bindings
			.credentials
			.insert(app_password_key(&hash), MailClass::Transactional);
	})
	.expect("bind");
	let directory = DirectoryHandle::new(
		crate::smtp::directory::Directory::new(
			["example.org".to_string()],
			[("alice@example.org".to_string(), "alice".to_string())],
		)
		.with_app_passwords([("alice".to_string(), app_password("notices", &hash))]),
	);
	let server = Server::new(
		"mail.example.org",
		Arc::new(ClassSink::default()) as Arc<dyn MessageSink>,
	)
	.with_directory(directory)
	.with_data_dir(dir.path().to_path_buf())
	.with_class_bindings(Arc::new(BindingSet::open(dir.path()).expect("bindings")));
	let mut bound = crate::smtp::session::Session::new("mail.example.org");
	bound.mark_authenticated_with_app_password_for_test("alice", "notices");
	let mut submitted = message("Epistle-Class: personal\r\n");
	assert_eq!(
		server
			.prepare_submission(&bound, "alice", &mut message(""))
			.expect("ok")
			.class,
		MailClass::Transactional
	);
	// The message cannot step the class down either.
	assert_eq!(
		server
			.prepare_submission(&bound, "alice", &mut submitted)
			.expect("ok")
			.class,
		MailClass::Transactional
	);
	let mut primary = crate::smtp::session::Session::new("mail.example.org");
	primary.mark_authenticated_for_test("alice");
	let mut upgrade = message("Epistle-Class: transactional\r\n");
	assert_eq!(
		server
			.prepare_submission(&primary, "alice", &mut upgrade)
			.expect("ok")
			.class,
		MailClass::Personal,
		"a header raised the class"
	);
	assert!(
		!String::from_utf8_lossy(&upgrade.data).contains("Epistle-Class"),
		"the class header reached the queue"
	);
}

/// Submit `data` as alice (account bound to `class`) and return the replies
/// after DATA, what reached the sink, and how many messages are in Sent.
async fn submit(
	class: MailClass,
	data: &[u8],
) -> (String, Vec<(AcceptedMessage, MailClass)>, usize) {
	submit_with(class, data, false).await
}

async fn submit_with(
	class: MailClass,
	data: &[u8],
	refuse: bool,
) -> (String, Vec<(AcceptedMessage, MailClass)>, usize) {
	let dir = tempfile::tempdir().expect("tempdir");
	update(dir.path(), |bindings| {
		bindings.accounts.insert("alice".into(), class);
	})
	.expect("bind");
	let (acceptor, cert) = crate::tls::test_support::acceptor_and_cert();
	let sink = Arc::new(ClassSink(Mutex::default(), refuse));
	let server = Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
		.with_directory(directory_with_password())
		.with_data_dir(dir.path().to_path_buf())
		.with_class_bindings(Arc::new(BindingSet::open(dir.path()).expect("bindings")))
		.with_tls(
			crate::tls::ReloadableAcceptor::new(acceptor),
			TlsMode::Opportunistic,
		);
	let (mut client, server_stream) = tokio::io::duplex(64 * 1024);
	let task = tokio::spawn(async move { server.handle(server_stream, None).await });
	assert!(reply(&mut client).await.starts_with("220 "));
	client
		.write_all(b"EHLO c.example.org\r\n")
		.await
		.expect("ehlo");
	let _ = reply(&mut client).await;
	client.write_all(b"STARTTLS\r\n").await.expect("starttls");
	assert!(reply(&mut client).await.starts_with("220 "));
	let name =
		tokio_rustls::rustls::pki_types::ServerName::try_from("mail.example.org").expect("name");
	let mut tls = connector(cert)
		.connect(name, client)
		.await
		.expect("handshake");
	tls.write_all(b"EHLO c.example.org\r\n")
		.await
		.expect("ehlo");
	let _ = reply(&mut tls).await;
	tls.write_all(b"AUTH LOGIN\r\n").await.expect("auth");
	assert!(reply(&mut tls).await.starts_with("334 "));
	tls.write_all(format!("{}\r\n", B64.encode("alice")).as_bytes())
		.await
		.expect("user");
	assert!(reply(&mut tls).await.starts_with("334 "));
	let password = crate::smtp::auth::tests::fixture_password().to_string();
	tls.write_all(format!("{}\r\n", B64.encode(&password)).as_bytes())
		.await
		.expect("pass");
	assert!(reply(&mut tls).await.starts_with("235 "), "auth");
	tls.write_all(b"MAIL FROM:<alice@example.org>\r\nRCPT TO:<bob@elsewhere.example>\r\nDATA\r\n")
		.await
		.expect("envelope");
	let mut batch = String::new();
	while !batch.contains("354 ") {
		batch.push_str(&reply(&mut tls).await);
	}
	tls.write_all(data).await.expect("data");
	tls.write_all(b".\r\n").await.expect("end");
	let after = reply(&mut tls).await;
	tls.write_all(b"QUIT\r\n").await.expect("quit");
	let _ = reply(&mut tls).await;
	drop(tls);
	task.await.expect("server task").expect("server result");
	let sent = std::fs::read_dir(dir.path().join("accounts/alice/folders/Sent/new"))
		.map(|entries| {
			entries
				.flatten()
				.filter(|entry| entry.path().extension().is_some_and(|ext| ext == "eml"))
				.count()
		})
		.unwrap_or(0);
	let messages = sink.0.lock().expect("lock").clone();
	(after, messages, sent)
}

#[tokio::test]
async fn transactional_smtp_mail_is_submitted_as_such_and_not_copied_to_sent() {
	let (after, submitted, sent) = submit(
		MailClass::Transactional,
		b"From: alice@example.org\r\nSubject: Aviso\r\n\r\nbody\r\n",
	)
	.await;
	assert!(after.starts_with("250 "), "{after}");
	assert_eq!(submitted.len(), 1);
	assert_eq!(submitted[0].1, MailClass::Transactional);
	assert_eq!(sent, 0, "transactional mail was copied to Sent");
	let (_, personal, sent) = submit(
		MailClass::Personal,
		b"From: alice@example.org\r\nSubject: hi\r\n\r\nbody\r\n",
	)
	.await;
	assert_eq!(personal[0].1, MailClass::Personal);
	assert_eq!(sent, 1, "personal mail keeps its Sent copy");
}

#[tokio::test]
async fn marketing_smtp_mail_without_one_click_is_refused() {
	let (after, submitted, _) = submit(
		MailClass::Marketing,
		b"From: alice@example.org\r\nSubject: offer\r\n\r\nbody\r\n",
	)
	.await;
	assert!(
		after.starts_with("550 5.7.1 marketing mail needs"),
		"{after}"
	);
	assert!(submitted.is_empty(), "the refused message reached the sink");
}

#[tokio::test]
async fn transactional_smtp_mail_that_cannot_be_recorded_gets_a_temporary_failure() {
	let (after, submitted, sent) = submit_with(
		MailClass::Transactional,
		b"From: alice@example.org\r\nSubject: Aviso\r\n\r\nbody\r\n",
		true,
	)
	.await;
	assert!(after.starts_with("451 4.3.0"), "{after}");
	assert!(submitted.is_empty());
	assert_eq!(sent, 0, "a refused message was copied to Sent");
}

#[test]
fn over_smtp_no_header_changes_the_class_bound_to_the_credential() {
	for bound in [
		MailClass::Personal,
		MailClass::Marketing,
		MailClass::Transactional,
	] {
		for asked in ["personal", "marketing", "transactional"] {
			let dir = tempfile::tempdir().expect("tempdir");
			let hash = crate::smtp::auth::tests::hash(crate::smtp::auth::tests::fixture_password());
			update(dir.path(), |bindings| {
				bindings.credentials.insert(app_password_key(&hash), bound);
			})
			.expect("bind");
			let directory = DirectoryHandle::new(
				crate::smtp::directory::Directory::new(
					["example.org".to_string()],
					[("alice@example.org".to_string(), "alice".to_string())],
				)
				.with_app_passwords([("alice".to_string(), app_password("notices", &hash))]),
			);
			let server = Server::new(
				"mail.example.org",
				Arc::new(ClassSink::default()) as Arc<dyn MessageSink>,
			)
			.with_directory(directory)
			.with_data_dir(dir.path().to_path_buf())
			.with_class_bindings(Arc::new(BindingSet::open(dir.path()).expect("bindings")));
			let mut session = crate::smtp::session::Session::new("mail.example.org");
			session.mark_authenticated_with_app_password_for_test("alice", "notices");
			// A one-click unsubscribe, so a marketing message is not refused.
			let mut data = message(&format!(
				"Epistle-Class: {asked}\r\nList-Unsubscribe: <https://example.org/u>\r\nList-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n"
			));
			let class = server
				.prepare_submission(&session, "alice", &mut data)
				.expect("accepted")
				.class;
			assert_eq!(class, bound, "bound to {bound}, the header says {asked}");
		}
	}
}
