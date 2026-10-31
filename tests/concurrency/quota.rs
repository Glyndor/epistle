//! Parallel DATA completions compete for the real mailbox's remaining bytes.

use super::{support::*, wire};
use epistle::smtp::quota::MailboxQuota;
use epistle::smtp::server::Server;
use epistle::storage::{LocalDelivery, MessageCrypto};
use std::sync::Arc;
use tokio::sync::Barrier;

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn parallel_deliveries_preserve_quota_and_every_250() {
	seed("quota");
	const LINES: usize = 512;
	let root = tempfile::tempdir().expect("mail store");
	let directory = directory();
	// Allow four full copies, including ample trace-header overhead, but not five.
	let limit = (message(0, LINES, false).len() * 4 + 4096) as u64;
	let sink = Arc::new(
		LocalDelivery::new(root.path(), directory.clone())
			.expect("local delivery")
			.with_quota(limit),
	);
	let quota = MailboxQuota::on_disk(root.path().to_path_buf(), MessageCrypto::disabled(), limit);
	let listener = Listener::start(
		Server::new("mx.epistle.test", sink)
			.with_directory(directory)
			.with_quota(Arc::new(quota)),
	)
	.await;
	// Initialise the mailbox through a real acknowledged delivery before racing
	// quota decisions, so folder creation is not a second variable.
	let mut control = listener.connect().await;
	data(&mut control, false).await;
	let mut baseline = message(TASKS, LINES, false);
	baseline.extend_from_slice(b".\r\n");
	wire::send(&mut control, &baseline).await;
	wire::expect(&mut control, wire::OK).await;
	wire::quit(&mut control).await;
	let barrier = Arc::new(Barrier::new(TASKS + 1));
	let mut tasks = tokio::task::JoinSet::new();
	for id in 0..TASKS {
		let mut stream = listener.connect().await;
		data(&mut stream, false).await;
		let barrier = barrier.clone();
		tasks.spawn(async move {
			// Queue the body before the barrier, so the race concentrates on finalisation.
			wire::send(&mut stream, &message(id, LINES, false)).await;
			barrier.wait().await;
			wire::send(&mut stream, b".\r\n").await;
			let reply = wire::line(&mut stream)
				.await
				.expect("DATA reply")
				.expect("open");
			assert!(
				reply == wire::OK || reply == "552 5.2.2 mailbox full\r\n",
				"seed={SEED:#x} id={id} unexpected rejection {reply:?}"
			);
			(id, reply == wire::OK)
		});
	}
	let accepted = tokio::time::timeout(DEADLINE, async {
		barrier.wait().await;
		let mut accepted = std::collections::BTreeMap::from([(TASKS, 1)]);
		while let Some(result) = tasks.join_next().await {
			let (id, ok) = result.expect("delivery task");
			if ok {
				accepted.insert(id, 1);
			}
		}
		accepted
	})
	.await
	.expect("quota race deadline");
	assert!(
		accepted.len() > 1,
		"seed={SEED:#x} no successful concurrent delivery"
	);
	let messages = mailbox(root.path());
	let bytes: u64 = messages.iter().map(|raw| raw.len() as u64).sum();
	let stored = inventory(messages, LINES, false);
	assert_eq!(
		stored, accepted,
		"seed={SEED:#x} every 250 stored exactly once"
	);
	assert!(
		bytes <= limit,
		"seed={SEED:#x} mailbox bytes={bytes} quota={limit} accepted={}",
		accepted.len()
	);
}

fn accepted_message(id: usize, lines: usize) -> epistle::smtp::session::AcceptedMessage {
	epistle::smtp::session::AcceptedMessage {
		reverse_path: "sender@remote.test".into(),
		recipients: vec!["tester@epistle.test".into()],
		data: message(id, lines, false),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: false,
		no_dsn: Vec::new(),
	}
}

fn account_mail(root: &std::path::Path, account: &str) -> Vec<Vec<u8>> {
	std::fs::read_dir(root.join("accounts").join(account).join("new"))
		.expect("read mailbox")
		.map(|entry| entry.expect("mailbox entry").path())
		.filter(|path| path.extension().is_some_and(|ext| ext == "eml"))
		.map(|path| std::fs::read(path).expect("read complete message"))
		.collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn parallel_alias_deliveries_preserve_each_members_quota() {
	use epistle::directory_store::DirectoryHandle;
	use epistle::smtp::directory::{AliasSpec, Directory};
	use epistle::smtp::sink::MessageSink;
	use epistle::storage::SplitDelivery;

	seed("alias quota");
	const LINES: usize = 512;
	// Exercise a full member both before and after the unlimited member.
	for healthy in ["aaa", "zzz"] {
		let root = tempfile::tempdir().expect("mail store");
		let limit = (message(0, LINES, false).len() * 3 + 4096) as u64;
		let directory = DirectoryHandle::new(
			Directory::new(
				["epistle.test".into()],
				[
					("tester@epistle.test".into(), "tester".into()),
					(format!("{healthy}@epistle.test"), healthy.into()),
				],
			)
			.with_account_quotas([("tester".into(), limit), (healthy.into(), 0)])
			.with_aliases([(
				"team@epistle.test".into(),
				AliasSpec {
					members: vec![
						"tester@epistle.test".into(),
						format!("{healthy}@epistle.test"),
					],
					senders: Vec::new(),
					hidden: true,
					list_id: Some("team.epistle.test".into()),
				},
			)]),
		);
		let sink =
			Arc::new(SplitDelivery::new(root.path(), directory.clone()).expect("routing sink"));
		sink.deliver(accepted_message(TASKS, LINES))
			.expect("initial copy");
		let listener = Listener::start(
			Server::new("mx.epistle.test", sink)
				.with_directory(directory)
				.with_quota(Arc::new(MailboxQuota::on_disk(
					root.path().to_path_buf(),
					MessageCrypto::disabled(),
					limit,
				))),
		)
		.await;
		let barrier = Arc::new(Barrier::new(TASKS + 1));
		let mut tasks = tokio::task::JoinSet::new();
		for id in 0..TASKS {
			let mut stream = listener.connect().await;
			wire::send(&mut stream, b"MAIL FROM:<sender@remote.test>\r\n").await;
			wire::expect(&mut stream, wire::OK).await;
			wire::send(&mut stream, b"RCPT TO:<team@epistle.test>\r\n").await;
			wire::expect(&mut stream, wire::OK).await;
			wire::send(&mut stream, b"DATA\r\n").await;
			wire::expect(
				&mut stream,
				"354 start mail input, end with <CRLF>.<CRLF>\r\n",
			)
			.await;
			let barrier = barrier.clone();
			tasks.spawn(async move {
				wire::send(&mut stream, &message(id, LINES, false)).await;
				barrier.wait().await;
				wire::send(&mut stream, b".\r\n").await;
				wire::expect(&mut stream, wire::OK).await;
				id
			});
		}
		let acknowledged = tokio::time::timeout(DEADLINE, async {
			barrier.wait().await;
			let mut acknowledged = std::collections::BTreeMap::new();
			while let Some(result) = tasks.join_next().await {
				acknowledged.insert(result.expect("alias delivery task"), 1);
			}
			acknowledged
		})
		.await
		.expect("alias race deadline");
		assert_eq!(acknowledged.len(), TASKS);
		let healthy_mail = account_mail(root.path(), healthy);
		assert!(
			healthy_mail
				.iter()
				.all(|raw| String::from_utf8_lossy(raw).contains("List-Id:"))
		);
		assert_eq!(
			inventory(healthy_mail, LINES, false),
			acknowledged,
			"every alias 250 reaches the member with room exactly once"
		);
		let limited = mailbox(root.path());
		let bytes: u64 = limited.iter().map(|raw| raw.len() as u64).sum();
		let stored = inventory(limited, LINES, false);
		assert_eq!(stored.len(), 3, "initial copy and two remaining admissions");
		assert_eq!(stored.get(&TASKS), Some(&1));
		assert!(
			stored
				.iter()
				.all(|(id, count)| *count == 1 && (*id == TASKS || acknowledged.contains_key(id)))
		);
		assert!(
			bytes <= limit,
			"seed={SEED:#x} alias bytes={bytes} quota={limit}"
		);
		// A new direct RCPT still reports 452 when the account is full.
		let remaining = limit - bytes;
		if remaining > 0 {
			let path = root
				.path()
				.join("accounts/tester/new")
				.join(format!("{}.eml", uuid::Uuid::now_v7()));
			std::fs::write(path, vec![b'x'; remaining as usize]).expect("fill remaining bytes");
		}
		let mut control = listener.connect().await;
		wire::send(&mut control, b"MAIL FROM:<sender@remote.test>\r\n").await;
		wire::expect(&mut control, wire::OK).await;
		wire::send(&mut control, b"RCPT TO:<tester@epistle.test>\r\n").await;
		wire::expect(&mut control, "452 4.2.2 mailbox full\r\n").await;
	}
}

/// Rendezvous after all three protocol checks and before local delivery.
/// This coordinates arrivals without serialising the storage operations.
struct DeliveryGate {
	inner: epistle::storage::SplitDelivery,
	arrivals: std::sync::Mutex<usize>,
	ready: std::sync::Condvar,
}

impl DeliveryGate {
	fn wait(&self) {
		let mut arrivals = self.arrivals.lock().expect("arrival lock");
		*arrivals += 1;
		self.ready.notify_all();
		let (_arrivals, result) = self
			.ready
			.wait_timeout_while(arrivals, DEADLINE, |n| *n < 3)
			.expect("arrival wait");
		assert!(
			!result.timed_out(),
			"all ingress paths must reach local delivery"
		);
	}
}

impl epistle::smtp::sink::MessageSink for DeliveryGate {
	fn deliver(
		&self,
		message: epistle::smtp::session::AcceptedMessage,
	) -> Result<(), epistle::smtp::sink::SinkError> {
		self.wait();
		epistle::smtp::sink::MessageSink::deliver(&self.inner, message)
	}

	fn submit(
		&self,
		message: epistle::smtp::session::AcceptedMessage,
		id: uuid::Uuid,
		account: &str,
		submission: &epistle::smtp::sink::Submission,
	) -> Result<(), epistle::smtp::sink::SinkError> {
		self.wait();
		epistle::smtp::sink::MessageSink::submit(&self.inner, message, id, account, submission)
	}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn incoming_submission_and_rest_share_final_copy_admission() {
	use axum::body::Body;
	use axum::http::{Request, StatusCode};
	use epistle::api::{ApiState, router};
	use epistle::directory_store::{AccountStore, DirectoryHandle};
	use epistle::smtp::sink::MessageSink;
	use epistle::storage::{FsSpool, SplitDelivery};
	use tower::ServiceExt;

	seed("mixed ingress quota");
	const LINES: usize = 512;
	let root = tempfile::tempdir().expect("mail store");
	let password = &*wire::PASSWORD;
	let hash = epistle::smtp::auth::hash_password(password).expect("password hash");
	let store = Arc::new(
		AccountStore::open(
			root.path(),
			vec!["epistle.test".into()],
			std::collections::HashMap::new(),
			vec![epistle::config::Account {
				name: "tester".into(),
				addresses: vec!["tester@epistle.test".into()],
				password_hash: Some(hash.clone()),
				quota_bytes: None,
				catch_all: Vec::new(),
				forward: Vec::new(),
				forward_keep_local: true,
				allowed_protocols: None,
				display_name: None,
			}],
		)
		.expect("account store"),
	);
	let directory = DirectoryHandle::new(
		wire::directory()
			.with_password_hashes([("tester".into(), hash.clone())])
			.with_save_sent([("tester".into(), false)]),
	);
	let initial = LocalDelivery::new(root.path(), directory.clone()).expect("initial sink");
	initial
		.deliver(accepted_message(TASKS, LINES))
		.expect("initial delivery");
	let initial_bytes = mailbox(root.path())[0].len();
	// One complete copy of any ingress fits; two of even the smallest do not.
	let limit = (initial_bytes + message(0, LINES, false).len() * 3 / 2) as u64;
	let sink = Arc::new(DeliveryGate {
		inner: SplitDelivery::new(root.path(), directory.clone())
			.expect("routing sink")
			.with_quota(limit),
		arrivals: std::sync::Mutex::new(0),
		ready: std::sync::Condvar::new(),
	});
	let tls = Tls::new();
	let listener = Listener::start(
		tls.server(
			Server::new("mx.epistle.test", sink.clone())
				.with_directory(directory)
				.with_quota(Arc::new(MailboxQuota::on_disk(
					root.path().to_path_buf(),
					MessageCrypto::disabled(),
					limit,
				))),
		),
	)
	.await;
	let mut incoming = listener.connect().await;
	data(&mut incoming, false).await;
	wire::send(&mut incoming, &message(0, LINES, false)).await;
	let mut submission = tls.connect(&listener).await;
	login(&mut submission, password).await;
	data(&mut submission, true).await;
	wire::send(&mut submission, &message(1, LINES, true)).await;
	let app = router(
		ApiState::new(
			&hash,
			root.path().to_path_buf(),
			vec!["epistle.test".into()],
			store.clone(),
			FsSpool::open(root.path()).expect("spool"),
		)
		.with_directory(store.handle())
		.with_quota(limit)
		.with_outbound(sink.clone()),
	);
	let api_text = "api quota copy\r\n".repeat(4096);
	let body = serde_json::json!({"from": "tester@epistle.test", "to": ["tester@epistle.test"],
		"subject": "api quota copy", "text": api_text, "save_sent": false});
	let request = Request::builder()
		.method("POST")
		.uri("/api/v1/send")
		.header("authorization", format!("Bearer {password}"))
		.header("content-type", "application/json")
		.body(Body::from(body.to_string()))
		.expect("request");
	let mut tasks = tokio::task::JoinSet::new();
	tasks.spawn(async move {
		wire::send(&mut incoming, b".\r\n").await;
		let reply = wire::line(&mut incoming)
			.await
			.expect("incoming reply")
			.expect("open");
		assert!(
			reply == wire::OK || reply == "552 5.2.2 mailbox full\r\n",
			"{reply:?}"
		);
		("incoming", reply == wire::OK)
	});
	tasks.spawn(async move {
		wire::send(&mut submission, b".\r\n").await;
		let reply = wire::line(&mut submission)
			.await
			.expect("submission reply")
			.expect("open");
		assert!(
			reply == wire::OK || reply == "552 5.2.2 mailbox full\r\n",
			"{reply:?}"
		);
		("submission", reply == wire::OK)
	});
	tasks.spawn(async move {
		let response = app.oneshot(request).await.expect("API response");
		let status = response.status();
		let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
			.await
			.expect("API body");
		let body: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON response");
		assert!(
			status == StatusCode::OK || status == StatusCode::INSUFFICIENT_STORAGE,
			"{status}: {body}"
		);
		if status == StatusCode::INSUFFICIENT_STORAGE {
			assert_eq!(body["error"]["code"], "mailbox_full");
		} else {
			assert!(body["queued"].as_str().is_some());
		}
		("api", status == StatusCode::OK)
	});
	let accepted = tokio::time::timeout(DEADLINE, async {
		let mut accepted = std::collections::BTreeMap::new();
		while let Some(result) = tasks.join_next().await {
			let (path, ok) = result.expect("ingress task");
			if ok {
				accepted.insert(path, 1);
			}
		}
		accepted
	})
	.await
	.expect("mixed race deadline");
	assert_eq!(*sink.arrivals.lock().expect("arrivals"), 3);
	assert_eq!(accepted.len(), 1, "one remaining complete copy");
	let messages = mailbox(root.path());
	let bytes: u64 = messages.iter().map(|raw| raw.len() as u64).sum();
	let mut stored = std::collections::BTreeMap::new();
	let mut baseline = 0;
	for raw in &messages {
		if raw.ends_with(&message(TASKS, LINES, false)) {
			baseline += 1;
			continue;
		}
		let path = if raw.ends_with(&message(0, LINES, false)) {
			"incoming"
		} else if raw.ends_with(&message(1, LINES, true)) {
			"submission"
		} else {
			let parsed = mail_parser::MessageParser::default()
				.parse(raw)
				.expect("stored MIME");
			assert_eq!(parsed.subject(), Some("api quota copy"));
			assert_eq!(
				parsed
					.body_text(0)
					.expect("API text")
					.replace("\r\n", "\n")
					.trim_end_matches('\n'),
				api_text.replace("\r\n", "\n").trim_end_matches('\n')
			);
			"api"
		};
		*stored.entry(path).or_insert(0) += 1;
	}
	assert_eq!(baseline, 1, "initial copy preserved");
	assert_eq!(
		stored, accepted,
		"every successful ingress stores exactly one complete copy"
	);
	assert!(
		bytes <= limit,
		"seed={SEED:#x} mixed bytes={bytes} quota={limit}"
	);
}
