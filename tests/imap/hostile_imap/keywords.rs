//! The keyword limits (32 per message, 64 bytes each) enforced through a real
//! session: STORE and APPEND must refuse a message over the cap, and leave the
//! message exactly as it was.

use super::harness::*;

const MESSAGE: &[u8] = b"Subject: keyword-canary\r\n\r\nbody\r\n";
const FIRST: &str = "F OK STORE completed\r\n";

fn keywords(count: usize) -> String {
	(0..count)
		.map(|n| format!("k{n}"))
		.collect::<Vec<_>>()
		.join(" ")
}

async fn with_message() -> (Harness, Tls) {
	let server = Harness::start(|s| s).await;
	let mut client = server.authenticated().await;
	append(&mut client, "").await;
	assert!(select_inbox(&mut client).await.contains("* 1 EXISTS\r\n"));
	(server, client)
}

async fn append(client: &mut Tls, flags: &str) -> String {
	let head = format!("A APPEND INBOX {flags}{{{}}}\r\n", MESSAGE.len());
	send(client, head.as_bytes()).await;
	let reply = line(client).await.expect("APPEND reply").expect("open");
	if reply != "+ ready for literal data\r\n" {
		return reply;
	}
	send(client, MESSAGE).await;
	send(client, b"\r\n").await;
	loop {
		let reply = line(client).await.expect("APPEND result").expect("open");
		if reply.starts_with("A ") {
			return reply;
		}
		assert!(reply.starts_with("* "), "{reply:?}");
	}
}

/// The FLAGS the one message carries, read back from the server.
async fn flags_of_message(client: &mut Tls) -> String {
	send(client, b"G FETCH 1 (FLAGS)\r\n").await;
	let fetch = line(client).await.expect("FETCH reply").expect("open");
	expect(client, "G OK FETCH completed\r\n").await;
	fetch
}

/// Everything up to the tagged reply of a STORE, which may carry untagged FETCH data.
async fn store(client: &mut Tls, command: &str) -> String {
	send(client, format!("{command}\r\n").as_bytes()).await;
	loop {
		let reply = line(client).await.expect("STORE reply").expect("open");
		if reply.starts_with("F ") {
			return reply;
		}
		assert!(reply.starts_with("* "), "{reply:?}");
	}
}

#[tokio::test]
async fn store_over_the_keyword_cap_is_refused_and_the_message_is_untouched() {
	let (server, mut client) = with_message().await;
	let over = store(&mut client, &format!("F STORE 1 FLAGS ({})", keywords(33))).await;
	assert_eq!(over, "F BAD too many keywords (max 32)\r\n");
	assert_eq!(
		flags_of_message(&mut client).await,
		"* 1 FETCH (FLAGS ())\r\n"
	);
	// Exactly at the cap is accepted, so the refusal above is the cap and not a broken harness.
	let at = store(&mut client, &format!("F STORE 1 FLAGS ({})", keywords(32))).await;
	assert_eq!(at, FIRST);
	let read = flags_of_message(&mut client).await;
	assert!(read.contains("(k0 ") && read.contains(" k31"), "{read:?}");
	noop(&mut client).await;
	server.healthy().await;
}

#[tokio::test]
async fn add_flags_that_would_overshoot_the_cap_changes_nothing() {
	let (server, mut client) = with_message().await;
	assert_eq!(
		store(&mut client, &format!("F STORE 1 FLAGS ({})", keywords(30))).await,
		FIRST
	);
	let before = flags_of_message(&mut client).await;
	// Two new keywords on top of thirty: thirty-two exactly, still allowed.
	assert_eq!(store(&mut client, "F STORE 1 +FLAGS (n1 n2)").await, FIRST);
	// One more is thirty-three.
	let over = store(&mut client, "F STORE 1 +FLAGS (n3)").await;
	assert_eq!(
		over,
		"F NO [LIMIT] too many keywords on a message (max 32)\r\n"
	);
	let after = flags_of_message(&mut client).await;
	assert!(after.contains(" n2") && !after.contains("n3"), "{after:?}");
	assert_ne!(before, after);
	server.healthy().await;
}

#[tokio::test]
async fn a_keyword_longer_than_64_bytes_is_refused_over_the_wire() {
	let (server, mut client) = with_message().await;
	let at = "a".repeat(64);
	let over = "a".repeat(65);
	assert_eq!(
		store(&mut client, &format!("F STORE 1 FLAGS ({over})")).await,
		"F BAD unsupported flag\r\n"
	);
	assert_eq!(
		flags_of_message(&mut client).await,
		"* 1 FETCH (FLAGS ())\r\n"
	);
	assert_eq!(
		store(&mut client, &format!("F STORE 1 FLAGS ({at})")).await,
		FIRST
	);
	assert!(flags_of_message(&mut client).await.contains(&at));
	server.healthy().await;
}

#[tokio::test]
async fn append_over_either_keyword_limit_is_refused_and_stores_no_message() {
	let (server, mut client) = with_message().await;
	for (flags, refusal) in [
		(
			format!("({}) ", keywords(33)),
			"A BAD too many keywords (max 32)\r\n",
		),
		(
			format!("({}) ", "a".repeat(65)),
			"A BAD unsupported flag\r\n",
		),
	] {
		let reply = append(&mut client, &flags).await;
		assert_eq!(reply, refusal);
		noop(&mut client).await;
	}
	send(&mut client, b"S SELECT INBOX\r\n").await;
	let mut exists = String::new();
	loop {
		let reply = line(&mut client).await.expect("SELECT").expect("open");
		if reply.ends_with("EXISTS\r\n") {
			exists = reply.clone();
		}
		if reply.starts_with("S ") {
			break;
		}
	}
	assert_eq!(
		exists, "* 1 EXISTS\r\n",
		"a refused APPEND stored a message"
	);
	// The same shape inside the limits is stored.
	let ok = append(&mut client, &format!("({}) ", keywords(32))).await;
	assert!(ok.starts_with("A OK [APPENDUID "), "{ok:?}");
	server.healthy().await;
}
