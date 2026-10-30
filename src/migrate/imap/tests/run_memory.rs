//! A source that lies about message sizes must not decide how much the
//! migration holds in memory.

use super::client::Client;
use super::fake_server::{FakeServer, Fault, Folder, Message, Mode, USER};
use super::parse::Listed;
use super::run::{DATE_1, Quiet, folders, local, migrate, settings};
use super::*;

const BODY: usize = 300 * 1024;

/// A message of about `BODY` octets with a Message-ID.
fn sized(uid: u32) -> Vec<u8> {
	let mut body =
		format!("Message-ID: <big-{uid}@old.example>\r\nSubject: {uid}\r\n\r\n").into_bytes();
	while body.len() < BODY {
		body.extend_from_slice(
			b"0123456789012345678901234567890123456789012345678901234567890\r\n",
		);
	}
	body
}

fn inbox(claimed: Option<u64>) -> Vec<Folder> {
	let mut all = folders();
	all[0].messages = (1..=4)
		.map(|uid| {
			let mut message = Message::new(uid, "", DATE_1, &sized(uid));
			message.claimed_size = claimed;
			message
		})
		.collect();
	all.truncate(1);
	all
}

#[tokio::test]
async fn sizes_declared_too_small_are_refused_and_a_rerun_stores_each_once() {
	let server = FakeServer::start(Mode::Tls, '.', inbox(Some(1024))).await;
	let dir = tempfile::tempdir().expect("tempdir");
	let mut settings = settings();
	settings.batch_messages = 10;
	settings.batch_bytes = 1024 * 1024;
	settings.limits.literal = 1024 * 1024;
	let (summary, error) = migrate(&server, dir.path(), &settings).await;
	assert!(
		matches!(
			error,
			Some(MigrateError::Client(ClientError::SizeMismatch {
				declared: 1024,
				..
			}))
		),
		"{error:?}"
	);
	assert_eq!(summary.copied, 0);
	assert!(
		local(dir.path(), "INBOX").is_empty(),
		"nothing of the lying batch is stored"
	);

	server.edit(|folders| {
		for message in &mut folders[0].messages {
			message.claimed_size = None;
		}
	});
	let (summary, error) = migrate(&server, dir.path(), &settings).await;
	assert!(error.is_none(), "{error:?}");
	assert_eq!(summary.copied, 4);
	let bodies: Vec<Vec<u8>> = local(dir.path(), "INBOX")
		.into_iter()
		.map(|m| m.2)
		.collect();
	assert_eq!(bodies, (1..=4).map(sized).collect::<Vec<_>>());
}

async fn logged_in(server: &FakeServer) -> Client {
	let source = super::run::source(server, Security::Tls);
	let mut client = Client::connect(&source.endpoint, settings().limits)
		.await
		.expect("connect");
	client.login(USER, &source.password).await.expect("login");
	client.examine(b"INBOX").await.expect("examine");
	client
}

#[tokio::test]
async fn a_batch_holds_no_more_than_its_budget() {
	let server = FakeServer::start(Mode::Tls, '.', inbox(None)).await;
	let batch: Vec<Listed> = (1..=4)
		.map(|uid| Listed {
			uid,
			size: sized(uid).len() as u64,
		})
		.collect();
	let total: u64 = batch.iter().map(|item| item.size).sum();
	let mut client = logged_in(&server).await;
	let refused = client.fetch(&batch, total - 1).await;
	assert!(
		matches!(refused, Err(ClientError::BatchTooLarge { budget }) if budget == total - 1),
		"{refused:?}"
	);
	let mut client = logged_in(&server).await;
	let fetched = client
		.fetch(&batch, total)
		.await
		.expect("just inside the budget");
	assert_eq!(fetched.len(), 4);
}

#[tokio::test]
async fn a_flood_of_unrelated_responses_ends_the_fetch() {
	let server = FakeServer::start(Mode::Tls, '.', inbox(None)).await;
	let batch = [Listed {
		uid: 1,
		size: sized(1).len() as u64,
	}];
	let mut client = logged_in(&server).await;
	server.set_fault(Fault::Flood { count: 1000 });
	let flooded = client.fetch(&batch, u64::MAX).await;
	assert!(
		matches!(&flooded, Err(ClientError::Protocol(text)) if text.contains("far more responses")),
		"{flooded:?}"
	);
	let mut client = logged_in(&server).await;
	server.set_fault(Fault::Flood { count: 60 });
	assert!(
		client.fetch(&batch, u64::MAX).await.is_ok(),
		"some noise is tolerated"
	);
	let _ = Quiet::default();
}

#[tokio::test]
async fn a_message_sent_twice_in_a_batch_is_stored_once() {
	let server = FakeServer::start(Mode::Tls, '.', inbox(None)).await;
	let dir = tempfile::tempdir().expect("tempdir");
	server.set_fault(Fault::RepeatFirst);
	let (summary, error) = migrate(&server, dir.path(), &settings()).await;
	assert!(error.is_none(), "{error:?}");
	let bodies: Vec<Vec<u8>> = local(dir.path(), "INBOX")
		.into_iter()
		.map(|m| m.2)
		.collect();
	assert_eq!(
		bodies,
		[sized(1), sized(3)],
		"each batch's first message, once each"
	);
	assert_eq!(summary.folders[0].vanished, 2);
}
