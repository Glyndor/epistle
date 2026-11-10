//! `maxObjectsInSet` and `maxConcurrentRequests` together, through real
//! sockets: four requests held open with their bodies unfinished use up the
//! credential's slots, a fifth is turned away before its body is read, and
//! once they hang up a set over the object cap is still refused whole.

use std::time::Duration;

use serde_json::{Map, Value, json};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use super::harness::{ADMIN, ALICE, DEADLINE, Harness, Wire};

const SET_CAP: usize = 500;
const SLOTS: usize = 4;

fn post(token: &str, body: &str) -> Vec<u8> {
	format!(
		"POST /jmap/api HTTP/1.1\r\nHost: jmap.test\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
		body.len()
	)
	.into_bytes()
}

/// The status line and the JSON body of one answer.
fn parsed(reply: &[u8]) -> (u16, Value) {
	let text = String::from_utf8_lossy(reply);
	let status = text
		.lines()
		.next()
		.and_then(|line| line.split_whitespace().nth(1))
		.and_then(|code| code.parse().ok())
		.unwrap_or_else(|| panic!("no status line: {text}"));
	let body = text.split_once("\r\n\r\n").map_or("", |(_, body)| body);
	(status, serde_json::from_str(body).unwrap_or(Value::Null))
}

/// One `Mailbox/set` with `create` new mailboxes and `destroy` ids that do not exist.
fn mailbox_set(create: usize, destroy: usize) -> String {
	let created: Map<String, Value> = (0..create)
		.map(|n| (format!("k{n}"), json!({"name": format!("box-{n}")})))
		.collect();
	let gone: Vec<String> = (0..destroy).map(|n| format!("missing-{n}")).collect();
	json!({"methodCalls": [[
		"Mailbox/set",
		{"accountId": "alice", "create": created, "destroy": gone},
		"set"
	]]})
	.to_string()
}

async fn mailboxes_named_box(wire: &Wire) -> usize {
	let body = json!({"methodCalls": [["Mailbox/get", {"accountId": "alice"}, "get"]]}).to_string();
	let (status, reply) = parsed(&wire.exchange(&post(ALICE, &body), false).await);
	assert_eq!(status, 200, "{reply}");
	reply["methodResponses"][0][1]["list"]
		.as_array()
		.expect("mailbox list")
		.iter()
		.filter(|m| m["name"].as_str().is_some_and(|n| n.starts_with("box-")))
		.count()
}

/// Open a connection whose body never completes, so its request holds a slot.
async fn held(wire: &Wire) -> TcpStream {
	let mut stream = TcpStream::connect(wire.addr).await.expect("connect");
	let head = format!(
		"POST /jmap/api HTTP/1.1\r\nHost: jmap.test\r\nAuthorization: Bearer {ALICE}\r\nContent-Type: application/json\r\nContent-Length: 1000000\r\n\r\n{{\"methodCalls\":"
	);
	stream.write_all(head.as_bytes()).await.expect("send head");
	stream
}

#[tokio::test]
async fn a_set_counts_creates_updates_and_destroys_together_over_the_wire() {
	let h = Harness::new();
	let wire = Wire::start(h.api.clone()).await;
	// 250 + 250 is exactly the cap: it runs, and every id that is not there is reported.
	let (status, reply) = parsed(
		&wire
			.exchange(&post(ALICE, &mailbox_set(250, 250)), false)
			.await,
	);
	assert_eq!(status, 200, "{reply}");
	assert_eq!(reply["methodResponses"][0][0], "Mailbox/set", "{reply}");
	assert_eq!(mailboxes_named_box(&wire).await, 250);
	// One more of any kind and the whole call is refused: nothing new is created.
	let (status, reply) = parsed(
		&wire
			.exchange(&post(ALICE, &mailbox_set(251, 250)), false)
			.await,
	);
	assert_eq!(status, 200, "{reply}");
	assert_eq!(
		reply["methodResponses"][0],
		json!(["error", {"type": "requestTooLarge"}, "set"])
	);
	assert_eq!(
		mailboxes_named_box(&wire).await,
		250,
		"a refused /set created mailboxes"
	);
	wire.healthy().await;
}

#[tokio::test]
async fn slots_held_by_unfinished_bodies_turn_the_next_request_away_before_its_set_runs() {
	let h = Harness::new();
	let wire = Wire::start(h.api.clone()).await;
	let mut open = Vec::new();
	for _ in 0..SLOTS {
		open.push(held(&wire).await);
	}
	// The slots are taken once the server has read the heads; the fifth waits for that.
	let over_cap = mailbox_set(SET_CAP, 1);
	let harmless = json!({"methodCalls": [["Core/echo", {}, "c"]]}).to_string();
	let started = tokio::time::Instant::now();
	let (status, reply) = loop {
		let (status, reply) = parsed(&wire.exchange(&post(ALICE, &harmless), false).await);
		if status == 429 || started.elapsed() > DEADLINE {
			break (status, reply);
		}
		// The heads were not all read yet and that request ran; try again.
		tokio::time::sleep(Duration::from_millis(50)).await;
	};
	assert_eq!(status, 429, "{reply}");
	assert_eq!(reply["limit"], "maxConcurrentRequests", "{reply}");
	// The same turned-away answer for a set that would also have been too large.
	let (status, reply) = parsed(&wire.exchange(&post(ALICE, &over_cap), false).await);
	assert_eq!(status, 429, "{reply}");
	assert_eq!(reply["limit"], "maxConcurrentRequests", "{reply}");
	// The limit is the credential's: the other key is not held back.
	let (status, reply) = parsed(&wire.exchange(&post(ADMIN, &mailbox_set(0, 1)), false).await);
	assert_eq!(status, 200, "{reply}");
	// They hang up, and the slots come back.
	drop(open);
	let started = tokio::time::Instant::now();
	let (status, reply) = loop {
		let (status, reply) = parsed(&wire.exchange(&post(ALICE, &over_cap), false).await);
		if status != 429 || started.elapsed() > DEADLINE {
			break (status, reply);
		}
		tokio::time::sleep(Duration::from_millis(50)).await;
	};
	assert_eq!(status, 200, "{reply}");
	assert_eq!(
		reply["methodResponses"][0],
		json!(["error", {"type": "requestTooLarge"}, "set"])
	);
	assert_eq!(
		mailboxes_named_box(&wire).await,
		0,
		"a request that was turned away or refused created mailboxes"
	);
	wire.healthy().await;
}
