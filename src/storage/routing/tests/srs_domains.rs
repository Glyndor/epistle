//! Forwarded mail and its bounces with a secret per hosted domain: each
//! domain signs with its own, a bounce returns only through the secret that
//! signed it, and an installation with one secret behaves as before.

use super::*;
use crate::queue::srs::{Srs, SrsKeys};
use crate::test_support::fixtures::fresh_secret;
use std::fs;

const OUR: &str = "relay.example";

fn directory() -> DirectoryHandle {
	DirectoryHandle::new(crate::smtp::directory::Directory::new(
		["a.example".to_string(), "b.example".to_string()],
		[
			("alice@a.example".to_string(), "alice".to_string()),
			("bob@b.example".to_string(), "bob".to_string()),
		],
	))
}

fn srs(secret: &str) -> Srs {
	Srs::new(secret.as_bytes())
}

fn incoming(to: &str) -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: "origsender@origin.example".into(),
		recipients: vec![to.to_string()],
		data: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: false,
		no_dsn: Vec::new(),
	}
}

fn bounce(to: &str) -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: String::new(),
		recipients: vec![to.to_string()],
		data: b"Subject: bounce\r\n\r\nfailed\r\n".to_vec(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: false,
		no_dsn: Vec::new(),
	}
}

/// A sink where alice (a.example) and bob (b.example) both redirect, plus
/// the data directory.
fn sink_with(keys: SrsKeys) -> (tempfile::TempDir, SplitDelivery) {
	let dir = tempfile::tempdir().expect("tempdir");
	for (account, to) in [
		("alice", "fwd-a@elsewhere.example"),
		("bob", "fwd-b@elsewhere.example"),
	] {
		let account_dir = dir.path().join("accounts").join(account);
		fs::create_dir_all(&account_dir).expect("mkdir");
		fs::write(
			account_dir.join("filter.sieve"),
			format!("redirect \"{to}\";"),
		)
		.expect("filter");
	}
	let sink = SplitDelivery::new(dir.path(), directory())
		.expect("sink")
		.with_srs_keys(keys, OUR);
	(dir, sink)
}

/// The envelope sender of every queued message, with its recipients.
fn queued(dir: &std::path::Path) -> Vec<(String, Vec<String>)> {
	let spool = FsSpool::open(dir).expect("spool");
	spool
		.list()
		.expect("list")
		.into_iter()
		.map(|id| {
			let entry = spool.load(id).expect("load");
			(entry.envelope.reverse_path, entry.envelope.recipients)
		})
		.collect()
}

fn sender_forwarded_to(dir: &std::path::Path, recipient: &str) -> String {
	queued(dir)
		.into_iter()
		.find(|(_, to)| to == &[recipient.to_string()])
		.unwrap_or_else(|| panic!("nothing was queued for {recipient}"))
		.0
}

fn local_part(address: &str) -> String {
	address.split_once('@').expect("an address").0.to_string()
}

#[test]
fn each_domain_forwards_under_its_own_secret_and_names_itself() {
	let (secret_a, secret_b) = (fresh_secret(), fresh_secret());
	let keys = SrsKeys::default()
		.with_domain("a.example", srs(&secret_a), None)
		.with_domain("b.example", srs(&secret_b), None);
	let (dir, sink) = sink_with(keys);
	sink.deliver(incoming("alice@a.example"))
		.expect("deliver a");
	sink.deliver(incoming("bob@b.example")).expect("deliver b");
	let from_a = sender_forwarded_to(dir.path(), "fwd-a@elsewhere.example");
	let from_b = sender_forwarded_to(dir.path(), "fwd-b@elsewhere.example");
	assert!(from_a.starts_with("SRS0.a.example="), "{from_a}");
	assert!(from_b.starts_with("SRS0.b.example="), "{from_b}");
	// Each is good only under the secret of the domain that signed it.
	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap()
		.as_secs()
		/ 86_400;
	assert!(
		srs(&secret_a)
			.reverse_for("a.example", &local_part(&from_a), now, 14)
			.is_some()
	);
	assert!(
		srs(&secret_b)
			.reverse_for("b.example", &local_part(&from_a), now, 14)
			.is_none()
	);
	assert!(
		srs(&secret_a)
			.reverse_for("a.example", &local_part(&from_b), now, 14)
			.is_none()
	);
}

#[test]
fn a_bounce_returns_to_the_sender_only_through_the_domain_that_signed_it() {
	let keys = SrsKeys::default()
		.with_domain("a.example", srs(&fresh_secret()), None)
		.with_domain("b.example", srs(&fresh_secret()), None);
	let (dir, sink) = sink_with(keys);
	sink.deliver(incoming("alice@a.example")).expect("deliver");
	let sender = sender_forwarded_to(dir.path(), "fwd-a@elsewhere.example");
	let local = local_part(&sender);

	// The bounce for a.example's forward returns to the original sender.
	sink.deliver(bounce(&sender)).expect("deliver bounce");
	let returned = queued(dir.path());
	assert!(
		returned
			.iter()
			.any(|(_, to)| to == &["origsender@origin.example".to_string()]),
		"the bounce did not return to the sender: {returned:?}"
	);

	// The same address retagged as b.example's goes nowhere near the sender.
	let forged = local.replacen("SRS0.a.example=", "SRS0.b.example=", 1);
	let (forge_dir, forge_sink) = sink_with(
		SrsKeys::default()
			.with_domain("a.example", srs(&fresh_secret()), None)
			.with_domain("b.example", srs(&fresh_secret()), None),
	);
	forge_sink
		.deliver(bounce(&format!("{forged}@{OUR}")))
		.expect("a refused address is not a delivery error");
	assert!(
		queued(forge_dir.path())
			.iter()
			.all(|(_, to)| to != &["origsender@origin.example".to_string()]),
		"a forged address was returned to the sender"
	);
}

#[test]
fn an_installation_with_one_secret_forwards_and_returns_as_it_did() {
	let secret = fresh_secret();
	let (dir, sink) = sink_with(SrsKeys::global_only(srs(&secret)));
	sink.deliver(incoming("alice@a.example")).expect("deliver");
	sink.deliver(incoming("bob@b.example")).expect("deliver");
	let from_a = sender_forwarded_to(dir.path(), "fwd-a@elsewhere.example");
	assert!(from_a.starts_with("SRS0="), "{from_a}");
	assert!(from_a.ends_with("@relay.example"), "{from_a}");
	sink.deliver(bounce(&from_a)).expect("bounce");
	assert!(
		queued(dir.path())
			.iter()
			.any(|(_, to)| to == &["origsender@origin.example".to_string()])
	);
}

#[test]
fn a_bounce_for_mail_forwarded_before_the_split_still_returns() {
	let global = fresh_secret();
	let old = SrsKeys::global_only(srs(&global));
	let (old_dir, old_sink) = sink_with(old);
	old_sink
		.deliver(incoming("alice@a.example"))
		.expect("deliver");
	let sent_before = sender_forwarded_to(old_dir.path(), "fwd-a@elsewhere.example");

	// The operator ran `epistle srs split`: a.example has its own secret and
	// the global one stays configured.
	let split = SrsKeys::default().with_global(srs(&global)).with_domain(
		"a.example",
		srs(&fresh_secret()),
		None,
	);
	let (dir, sink) = sink_with(split);
	sink.deliver(bounce(&sent_before)).expect("bounce");
	assert!(
		queued(dir.path())
			.iter()
			.any(|(_, to)| to == &["origsender@origin.example".to_string()]),
		"a bounce for mail forwarded before the split was lost"
	);
}
