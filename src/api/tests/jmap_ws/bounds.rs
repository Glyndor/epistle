//! A JMAP WebSocket costs the server a listener slot for as long as it is
//! open. One caller may hold [`MAX`] of them, and a socket that sends nothing
//! is closed once [`IDLE_TIMEOUT`] passes. The idle tests run on the paused
//! runtime clock, so they take no real time.

use super::revoke::{ANN, CAROL, Client, serve, ws_state};
use crate::api::jmap::websocket::bounds::{IDLE_TIMEOUT, MAX_SOCKETS_PER_CALLER as MAX};
use serde_json::json;
use std::time::Duration;

/// A little longer than the idle timeout.
const PAST_IDLE: Duration = Duration::from_secs(IDLE_TIMEOUT.as_secs() + 1);

fn echo(id: &str) -> serde_json::Value {
	json!({
		"@type": "Request",
		"id": id,
		"using": ["urn:ietf:params:jmap:core"],
		"methodCalls": [["Core/echo", {}, "c1"]],
	})
}

async fn assert_closed_idle(client: &mut Client) {
	let (opcode, payload) = client.next_within(PAST_IDLE * 2).await;
	assert_eq!(opcode, 8, "expected a close frame");
	assert_eq!(
		payload.get(..2),
		Some(&1001u16.to_be_bytes()[..]),
		"close code"
	);
}

#[tokio::test]
async fn the_socket_past_the_cap_is_refused_and_another_account_is_not() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (state, _store) = ws_state(dir.path());
	let addr = serve(state).await;
	let mut held = Vec::new();
	for _ in 0..MAX {
		held.push(Client::connect(addr, ANN).await.expect("within the cap"));
	}
	let refusal = Client::connect(addr, ANN)
		.await
		.err()
		.expect("past the cap");
	assert!(refusal.starts_with("HTTP/1.1 429"), "{refusal}");
	// Another account has its own count.
	let mut other = Client::connect(addr, CAROL).await.expect("other account");
	other.send(&echo("other")).await;
	assert_eq!(other.next_json().await["requestId"], "other");
	// The sockets that were open keep working.
	for client in held.iter_mut() {
		client.send(&echo("held")).await;
		assert_eq!(client.next_json().await["requestId"], "held");
	}
	// Hanging up one gives its place back.
	drop(held.pop());
	let mut reopened = None;
	for _ in 0..100 {
		match Client::connect(addr, ANN).await {
			Ok(client) => {
				reopened = Some(client);
				break;
			}
			Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
		}
	}
	assert!(reopened.is_some(), "the slot was not given back");
}

#[tokio::test(start_paused = true)]
async fn an_idle_socket_is_closed_and_gives_its_slot_back() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (state, _store) = ws_state(dir.path());
	let addr = serve(state).await;
	let mut held = Vec::new();
	for _ in 0..MAX {
		held.push(Client::connect(addr, ANN).await.expect("within the cap"));
	}
	assert!(Client::connect(addr, ANN).await.is_err(), "past the cap");
	// Nothing is sent: the server closes each socket once the time is up.
	for client in held.iter_mut() {
		assert_closed_idle(client).await;
	}
	let mut fresh = Client::connect(addr, ANN)
		.await
		.expect("a closed socket gives its place back");
	fresh.send(&echo("fresh")).await;
	assert_eq!(fresh.next_json().await["requestId"], "fresh");
}

#[tokio::test(start_paused = true)]
async fn a_socket_that_keeps_sending_is_not_closed() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (state, _store) = ws_state(dir.path());
	let mut client = Client::open(state, ANN).await;
	// Well past the idle time in total, but never idle for that long: a
	// request, then a ping, each inside the window.
	for round in 0..4 {
		tokio::time::sleep(IDLE_TIMEOUT - Duration::from_secs(10)).await;
		if round % 2 == 0 {
			client.send(&echo("alive")).await;
			let reply = client.next_within(PAST_IDLE).await;
			assert_eq!(reply.0, 1, "the socket was closed while active");
		} else {
			client.send_frame(0x9, b"hi").await;
			let (opcode, payload) = client.next_within(PAST_IDLE).await;
			assert_eq!((opcode, payload.as_slice()), (0xA, &b"hi"[..]), "pong");
		}
	}
	client.send(&echo("last")).await;
	assert_eq!(client.next_json().await["requestId"], "last");
}
