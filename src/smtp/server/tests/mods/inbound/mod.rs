//! The inbound decisions of `[smtp]` and `[antispam]` on the wire: the
//! operator's own relays, the full-mailbox answer and the greylist.

use std::sync::Arc;

use super::scopes::{Run, dns, plain, run, script, server};
use crate::antispam::greylist::{GreylistStore, MemoryGreylist, Triplet};
use crate::smtp::server::InboundPolicy;
use crate::smtp::sink::MemorySink;

mod mailbox_full;
mod trusted;

/// The policy `extra` sets: `[smtp]` and `[antispam]` text.
fn policy(extra: &str) -> InboundPolicy {
	use std::io::Write;
	let mut file = tempfile::NamedTempFile::new().expect("config file");
	writeln!(
		file,
		"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n{extra}"
	)
	.expect("write config");
	InboundPolicy::from_config(&crate::config::Config::load(file.path()).expect("config loads"))
}

const CLIENT: &str = "192.0.2.7";
const TRUST_CLIENT: &str = "[smtp]\ntrusted_networks = [\"192.0.2.0/24\"]\n";
const GREYLISTED: &str = "451 4.7.1 greylisted";

fn greylist() -> Arc<MemoryGreylist> {
	Arc::new(MemoryGreylist::new())
}

fn key(ip: &str, recipient: &str) -> String {
	Triplet {
		client_ip: ip.parse().expect("ip"),
		sender: "a@example.net",
		recipient,
	}
	.key()
}

async fn deliver_to(
	server: crate::smtp::server::Server,
	sink: &Arc<MemorySink>,
	to: &[&str],
) -> Run {
	run(
		server,
		sink,
		&script("a@example.net", to, &plain("a@example.net")),
	)
	.await
}

#[tokio::test]
async fn control_a_stranger_is_greylisted() {
	let sink = Arc::new(MemorySink::new());
	let run = deliver_to(
		server(&sink, None).with_greylist(greylist(), 600),
		&sink,
		&["bob@example.org"],
	)
	.await;
	assert!(run.output.contains(GREYLISTED), "{}", run.output);
}

#[tokio::test]
async fn every_recipient_has_a_triplet_recorded_on_the_first_attempt() {
	let sink = Arc::new(MemorySink::new());
	let store = greylist();
	let run = deliver_to(
		server(&sink, None).with_greylist(store.clone(), 600),
		&sink,
		&["bob@example.org", "alice@example.org"],
	)
	.await;
	assert!(run.output.contains(GREYLISTED), "{}", run.output);
	for recipient in ["bob@example.org", "alice@example.org"] {
		let seen = store.first_seen(&key(CLIENT, recipient)).await;
		assert!(matches!(seen, Ok(Some(_))), "{recipient}: {seen:?}");
	}
}

#[tokio::test]
async fn a_second_recipient_not_yet_seen_defers_the_message_too() {
	let sink = Arc::new(MemorySink::new());
	let store = greylist();
	// Bob's triplet is old enough, alice's is new.
	store.record(&key(CLIENT, "bob@example.org"), 1).await;
	let run = deliver_to(
		server(&sink, None).with_greylist(store.clone(), 600),
		&sink,
		&["bob@example.org", "alice@example.org"],
	)
	.await;
	assert!(run.output.contains(GREYLISTED), "{}", run.output);
	assert!(run.messages.is_empty());
	let seen = store.first_seen(&key(CLIENT, "alice@example.org")).await;
	assert!(matches!(seen, Ok(Some(_))), "{seen:?}");
}

#[tokio::test]
async fn a_mask_lets_a_retry_from_a_neighbour_through() {
	// The triplet was first seen long ago from another host of the /24.
	let seeded = |store: &Arc<MemoryGreylist>| {
		let store = store.clone();
		async move { store.record(&key("192.0.2.0", "bob@example.org"), 1).await }
	};
	let sink = Arc::new(MemorySink::new());
	let store = greylist();
	seeded(&store).await;
	let masked = policy("[antispam]\ngreylist_mask_v4 = 24\n");
	let run = deliver_to(
		server(&sink, None)
			.with_greylist(store, 600)
			.with_inbound_policy(masked),
		&sink,
		&["bob@example.org"],
	)
	.await;
	assert_eq!(run.messages.len(), 1, "{}", run.output);
	// Without the mask the same client is a stranger.
	let sink = Arc::new(MemorySink::new());
	let store = greylist();
	seeded(&store).await;
	let run = deliver_to(
		server(&sink, None).with_greylist(store, 600),
		&sink,
		&["bob@example.org"],
	)
	.await;
	assert!(run.output.contains(GREYLISTED), "{}", run.output);
}

#[test]
fn the_default_policy_trusts_nobody() {
	let policy = InboundPolicy::default();
	assert!(!policy.trusts(Some(CLIENT.parse().expect("ip"))));
	assert!(!policy.trusts(None));
}
