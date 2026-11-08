//! The outbound delivery events of a message go to the webhook of the tenant
//! that owns the entry, and to no other. The owner is what the server decided
//! when it queued the entry, never the envelope sender the sender wrote.

use std::collections::BTreeMap;

use super::*;
use crate::queue::tests::test_remote::{FakeRemote, Script};
use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::{MemorySink, MessageSink};
use crate::test_fixtures::fresh_secret;
use crate::webhook::tests::support::{bodies, quiet, settle, signed_receiver, tenant_config};

fn from_to(sender: &str, recipient: &str) -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: sender.into(),
		recipients: vec![recipient.into()],
		data: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: false,
		no_dsn: Vec::new(),
	}
}

/// A remote that refuses every recipient named, for good.
fn refusing(recipients: &[&str]) -> FakeRemote {
	let remote = FakeRemote::default();
	let mut script = Script::default();
	for recipient in recipients {
		script.rcpt.insert(
			format!("{recipient}@remote.example"),
			"550 5.1.1 no such user".into(),
		);
	}
	remote.script("remote.example", script);
	remote
}

struct Receivers {
	webhook: crate::webhook::Webhook,
	default: crate::webhook::tests::support::Received,
	alpha: crate::webhook::tests::support::Received,
	beta: crate::webhook::tests::support::Received,
}

async fn receivers() -> Receivers {
	let (default_url, default) = signed_receiver().await;
	let (alpha_url, alpha) = signed_receiver().await;
	let (beta_url, beta) = signed_receiver().await;
	let config = tenant_config(
		Some((&default_url, &fresh_secret())),
		Some((&alpha_url, &fresh_secret())),
		Some((&beta_url, &fresh_secret())),
	);
	Receivers {
		webhook: crate::webhook::from_config(&config).expect("a poster"),
		default,
		alpha,
		beta,
	}
}

#[tokio::test]
async fn each_entrys_events_reach_the_tenant_that_owns_it() {
	let r = receivers().await;
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("spool");
	for (sender, recipient, owner) in [
		("alice@a.example", "carol@remote.example", Some("a.example")),
		("bob@b.example", "dave@remote.example", Some("b.example")),
		// Queued before entries had an owner: the sender names alpha's domain,
		// and that is not enough to be alpha's.
		("legacy@a.example", "frank@remote.example", None),
	] {
		spool
			.store_owned(&from_to(sender, recipient), owner, &BTreeMap::new())
			.expect("store");
	}
	let worker = Worker::new(
		spool,
		Arc::new(refusing(&["carol", "dave", "frank"])),
		"mail.a.example",
	)
	.with_bounce_sink(Arc::new(MemorySink::new()) as Arc<dyn MessageSink>)
	.with_webhook(Arc::new(r.webhook));
	worker.pass().await.expect("pass");

	settle(|| {
		!bodies(&r.alpha).is_empty()
			&& !bodies(&r.beta).is_empty()
			&& !bodies(&r.default).is_empty()
	})
	.await;
	quiet().await;
	let (alpha, beta, default) = (bodies(&r.alpha), bodies(&r.beta), bodies(&r.default));
	assert_eq!((alpha.len(), beta.len(), default.len()), (1, 1, 1));
	assert!(alpha[0].contains("carol@remote.example"), "{}", alpha[0]);
	assert!(beta[0].contains("dave@remote.example"), "{}", beta[0]);
	assert!(
		default[0].contains("frank@remote.example"),
		"an entry with no owner must use the server-wide webhook: {}",
		default[0]
	);
}

#[tokio::test]
async fn a_forged_sender_in_another_tenants_domain_does_not_move_the_events() {
	let r = receivers().await;
	let dir = tempfile::tempdir().expect("tempdir");
	let directory =
		crate::directory_store::DirectoryHandle::new(crate::smtp::directory::Directory::new(
			["a.example".to_string(), "b.example".to_string()],
			[
				("alice@a.example".to_string(), "alice".to_string()),
				("bob@b.example".to_string(), "bob".to_string()),
			],
		));
	let sink = crate::storage::SplitDelivery::new(dir.path(), directory).expect("sink");
	// Alice, of tenant alpha, authenticates and writes MAIL FROM in beta's
	// domain.
	sink.submit(
		from_to("ceo@b.example", "carol@remote.example"),
		uuid::Uuid::now_v7(),
		"alice",
		&crate::smtp::sink::Submission::default(),
	)
	.expect("accepted");
	let spool = FsSpool::open(dir.path()).expect("spool");
	let id = spool.list().expect("list")[0];
	assert_eq!(
		spool.load(id).expect("entry").envelope.owner.as_deref(),
		Some("a.example"),
		"the owner is the authenticated account's domain, not the forged sender's"
	);
	let worker = Worker::new(spool, Arc::new(refusing(&["carol"])), "mail.a.example")
		.with_bounce_sink(Arc::new(MemorySink::new()) as Arc<dyn MessageSink>)
		.with_webhook(Arc::new(r.webhook));
	worker.pass().await.expect("pass");

	settle(|| !bodies(&r.alpha).is_empty()).await;
	quiet().await;
	assert_eq!(
		bodies(&r.alpha).len(),
		1,
		"alpha gets its own account's event"
	);
	assert!(
		bodies(&r.beta).is_empty(),
		"beta saw an event of alpha's account"
	);
	assert!(bodies(&r.default).is_empty());
}

#[test]
fn an_envelope_written_before_the_owner_existed_reads_as_ownerless() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("spool");
	let id = spool
		.store_owned(
			&from_to("alice@a.example", "carol@remote.example"),
			Some("a.example"),
			&BTreeMap::new(),
		)
		.expect("store");
	let mut json = serde_json::to_value(spool.load(id).expect("entry").envelope).expect("json");
	assert_eq!(json["owner"], "a.example");
	json.as_object_mut().expect("object").remove("owner");
	let old: crate::storage::Envelope = serde_json::from_value(json).expect("an old envelope");
	assert_eq!(old.owner, None);
}
