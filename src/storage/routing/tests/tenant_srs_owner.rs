//! A bounce that returns through a domain's SRS address belongs to that domain
//! when nobody authenticated: the domain the address's HMAC proved.

use super::*;
use crate::queue::srs::{Srs, SrsKeys};
use crate::smtp::sink::MessageSink;
use crate::test_support::fixtures::fresh_secret;

fn directory() -> DirectoryHandle {
	DirectoryHandle::new(crate::smtp::directory::Directory::new(
		["a.example".to_string(), "b.example".to_string()],
		[
			("alice@a.example".to_string(), "alice".to_string()),
			("bob@b.example".to_string(), "bob".to_string()),
		],
	))
}

fn bounce(to: &str) -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: String::new(),
		recipients: vec![to.into()],
		data: b"Subject: bounce\r\n\r\nfailed\r\n".to_vec(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: false,
		no_dsn: Vec::new(),
	}
}

fn now_days() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs() / 86_400)
		.unwrap_or(0)
}

/// Two hosted domains with a secret each.
struct Secrets {
	a: String,
	b: String,
}

impl Secrets {
	fn new() -> Self {
		Secrets {
			a: fresh_secret(),
			b: fresh_secret(),
		}
	}

	fn keys(&self) -> SrsKeys {
		SrsKeys::default()
			.with_domain("a.example", Srs::new(self.a.as_bytes()), None)
			.with_domain("b.example", Srs::new(self.b.as_bytes()), None)
	}

	/// The return address `domain` would have put on forwarded mail.
	fn address(&self, domain: &str) -> String {
		let local = self
			.keys()
			.forward(
				domain,
				("origsender", "origin.example"),
				"relay.example",
				now_days(),
			)
			.expect("signed");
		format!(
			"{}@relay.example",
			local.split_once('@').expect("address").0
		)
	}
}

fn owner_of_the_only_entry(root: &std::path::Path) -> Option<String> {
	let spool = FsSpool::open(root).expect("spool");
	let ids = spool.list().expect("list");
	assert_eq!(ids.len(), 1);
	spool.load(ids[0]).expect("entry").envelope.owner
}

#[test]
fn an_unauthenticated_srs_return_is_owned_by_the_domain_that_signed_it() {
	let secrets = Secrets::new();
	for domain in ["a.example", "b.example"] {
		let dir = tempfile::tempdir().expect("tempdir");
		let sink = SplitDelivery::new(dir.path(), directory())
			.expect("sink")
			.with_srs_keys(secrets.keys(), "relay.example");
		sink.deliver(bounce(&secrets.address(domain)))
			.expect("accepted");
		assert_eq!(owner_of_the_only_entry(dir.path()).as_deref(), Some(domain));
	}
}

#[test]
fn a_retagged_srs_return_is_refused_and_queues_nothing_for_the_other_domain() {
	let secrets = Secrets::new();
	let forged = secrets
		.address("a.example")
		.replacen("SRS0.a.example=", "SRS0.b.example=", 1);
	let dir = tempfile::tempdir().expect("tempdir");
	let sink = SplitDelivery::new(dir.path(), directory())
		.expect("sink")
		.with_srs_keys(secrets.keys(), "relay.example");
	sink.deliver(bounce(&forged)).expect("handled");
	// Not recognised as an SRS return: it is not queued back to the sender
	// under b.example's name.
	let spool = FsSpool::open(dir.path()).expect("spool");
	for id in spool.list().expect("list") {
		let envelope = spool.load(id).expect("entry").envelope;
		assert_ne!(envelope.owner.as_deref(), Some("b.example"));
		assert!(
			!envelope
				.recipients
				.contains(&"origsender@origin.example".to_string())
		);
	}
}

#[test]
fn an_srs_return_of_the_older_shape_has_no_domain_to_own_it() {
	let secret = fresh_secret();
	let srs = Srs::new(secret.as_bytes());
	let local = srs
		.forward("origsender", "origin.example", "relay.example", now_days())
		.split_once('@')
		.expect("address")
		.0
		.to_string();
	let dir = tempfile::tempdir().expect("tempdir");
	let sink = SplitDelivery::new(dir.path(), directory())
		.expect("sink")
		.with_srs(Srs::new(secret.as_bytes()), "relay.example");
	sink.deliver(bounce(&format!("{local}@relay.example")))
		.expect("accepted");
	assert_eq!(owner_of_the_only_entry(dir.path()), None);
}
