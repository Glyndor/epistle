//! Inbound attachment inspections run on the blocking pool, so a flood of
//! heavy messages could take every blocking thread and stall unrelated
//! blocking work (DNS, disk). They are capped in total and per client,
//! past the cap the message is deferred with a `451`, and an inspection
//! that panics is a `451` too, never a dead session.

use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncWriteExt, DuplexStream};

use super::tests_auth::{directory_with_password, reply};
use super::*;
use crate::antispam::attachments::policy::Policy;
use crate::config::{AttachmentMode, Attachments};
use crate::smtp::sink::MemorySink;

const BUSY: &str = "451 4.7.1 content scan unavailable, try again later\r\n";

const MESSAGE: &str = "From: x@example.net\r\nTo: alice@example.org\r\nSubject: s\r\n\r\nhello\r\n";

/// Inspections stay inside the hook while this is `true`.
static HOLD: (Mutex<bool>, Condvar) = (Mutex::new(true), Condvar::new());
/// Inspections that reached the hook.
static ENTERED: AtomicUsize = AtomicUsize::new(0);

fn hold() {
	ENTERED.fetch_add(1, Ordering::SeqCst);
	let mut held = HOLD.0.lock().expect("hold lock");
	while *held {
		held = HOLD.1.wait(held).expect("hold wait");
	}
}

fn release() {
	*HOLD.0.lock().expect("hold lock") = false;
	HOLD.1.notify_all();
}

/// Lets held inspections go when the test ends, also when it fails, so no
/// blocking thread is left waiting.
struct Release;

impl Drop for Release {
	fn drop(&mut self) {
		release();
	}
}

/// The next reply, or a marker when none comes in time.
async fn answer(client: &mut DuplexStream) -> String {
	tokio::time::timeout(Duration::from_secs(10), reply(client))
		.await
		.unwrap_or_else(|_| "no reply in time".to_string())
}

fn explode() {
	panic!("inspection failed on purpose");
}

fn policy() -> Policy {
	let section = Attachments {
		mode: AttachmentMode::Quarantine,
		..Attachments::default()
	};
	Policy::from_config(&section, 1 << 20).expect("mode is not off")
}

/// Open a session from `peer`, send one message and leave the reply to the
/// end of DATA unread.
async fn send(policy: &Arc<Policy>, peer: &str) -> DuplexStream {
	let server = Server::new("mail.example.org", Arc::new(MemorySink::new()))
		.with_directory(directory_with_password())
		.with_attachment_policy(Arc::clone(policy));
	let peer: IpAddr = peer.parse().expect("address");
	let (mut client, stream) = tokio::io::duplex(64 * 1024);
	tokio::spawn(async move { server.handle(stream, Some(peer)).await });
	assert!(reply(&mut client).await.starts_with("220 "));
	client
		.write_all(
			b"EHLO c.example.net\r\nMAIL FROM:<x@example.net>\r\nRCPT TO:<alice@example.org>\r\nDATA\r\n",
		)
		.await
		.expect("envelope");
	let mut batch = String::new();
	while !batch.contains("354 ") {
		batch.push_str(&reply(&mut client).await);
	}
	client
		.write_all(format!("{MESSAGE}.\r\n").as_bytes())
		.await
		.expect("data");
	client
}

async fn entered(count: usize) {
	let deadline = Instant::now() + Duration::from_secs(10);
	while ENTERED.load(Ordering::SeqCst) < count {
		assert!(
			Instant::now() < deadline,
			"inspection {count} never started"
		);
		tokio::time::sleep(Duration::from_millis(2)).await;
	}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_flood_from_one_client_is_deferred_and_others_keep_their_share() {
	let _release = Release;
	let policy = Arc::new(policy().with_inbound_caps(2, 1).with_check_hook(hold));
	let mut first = send(&policy, "192.0.2.1").await;
	entered(1).await;
	let mut flood = Vec::new();
	for _ in 0..5 {
		flood.push(send(&policy, "192.0.2.1").await);
	}
	for client in &mut flood {
		assert_eq!(answer(client).await, BUSY, "the client is at its share");
	}
	let mut other = send(&policy, "198.51.100.7").await;
	entered(2).await;
	let mut third = send(&policy, "203.0.113.9").await;
	assert_eq!(answer(&mut third).await, BUSY, "the server is at its cap");
	assert_eq!(ENTERED.load(Ordering::SeqCst), 2, "nothing past a cap ran");
	release();
	assert!(answer(&mut first).await.starts_with("250 "));
	assert!(answer(&mut other).await.starts_with("250 "));
	let mut again = send(&policy, "192.0.2.1").await;
	assert!(
		answer(&mut again).await.starts_with("250 "),
		"the slots came back"
	);
}

#[test]
fn one_ipv6_client_is_its_whole_64() {
	let policy = policy().with_inbound_caps(4, 1);
	let held = policy
		.admit_inbound(Some("2001:db8::1".parse().expect("address")))
		.expect("slot");
	assert!(
		policy
			.admit_inbound(Some("2001:db8::ffff".parse().expect("address")))
			.is_none(),
		"same /64"
	);
	assert!(
		policy
			.admit_inbound(Some("2001:db8:0:1::1".parse().expect("address")))
			.is_some(),
		"another /64"
	);
	drop(held);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_panicking_inspection_defers_the_message_and_the_session_goes_on() {
	let policy = Arc::new(policy().with_check_hook(explode));
	let mut client = send(&policy, "192.0.2.50").await;
	assert_eq!(answer(&mut client).await, BUSY);
	client.write_all(b"NOOP\r\n").await.expect("noop");
	assert!(reply(&mut client).await.starts_with("250 "));
	client.write_all(b"QUIT\r\n").await.expect("quit");
	assert!(reply(&mut client).await.starts_with("221 "));
}

fn slow() {
	std::thread::sleep(Duration::from_secs(7));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_inspection_past_its_deadline_defers_the_message() {
	// The inspection's own deadline is checked between parts; this one is
	// stuck inside a single step, and the session stops waiting for it.
	let policy = Arc::new(policy().with_timeout(Duration::ZERO).with_check_hook(slow));
	let started = Instant::now();
	let mut client = send(&policy, "192.0.2.60").await;
	assert_eq!(answer(&mut client).await, BUSY);
	assert!(
		started.elapsed() < Duration::from_secs(7),
		"it did not wait"
	);
}
