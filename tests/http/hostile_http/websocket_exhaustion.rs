//! Upgrades must retain listener admission and share caller limits across ports.

use std::net::SocketAddr;
use std::time::Duration;

use axum::Router;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use super::harness::{ADMIN, ALICE, DEADLINE, Harness, Wire};

struct Abort(tokio::task::AbortHandle);
impl Drop for Abort {
	fn drop(&mut self) {
		self.0.abort();
	}
}

async fn upgrade(addr: SocketAddr, token: &str) -> (TcpStream, String) {
	timeout(DEADLINE, async {
		let mut stream = TcpStream::connect(addr).await.expect("connect");
		let head = format!(
			"GET /jmap/ws HTTP/1.1\r\nHost: example.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nAuthorization: Bearer {token}\r\n\r\n"
		);
		stream.write_all(head.as_bytes()).await.expect("upgrade");
		let mut reply = Vec::new();
		while !reply.ends_with(b"\r\n\r\n") {
			reply.push(stream.read_u8().await.expect("upgrade response"));
			assert!(reply.len() <= 8192, "unbounded handshake response");
		}
		(stream, String::from_utf8(reply).expect("HTTP head"))
	}).await.expect("upgrade deadline")
}

async fn ping(stream: &mut TcpStream) {
	timeout(DEADLINE, async {
		// FIN, PING, masked payload "x". The server's PONG is unmasked.
		stream
			.write_all(&[0x89, 0x81, 1, 2, 3, 4, b'x' ^ 1])
			.await
			.expect("ping");
		let mut pong = [0; 3];
		stream.read_exact(&mut pong).await.expect("pong");
		assert_eq!(pong, [0x8a, 1, b'x']);
	})
	.await
	.expect("ping deadline");
}

#[tokio::test]
async fn a_caller_cannot_multiply_its_socket_budget_by_switching_listeners() {
	let h = Harness::new();
	let one = Wire::start(h.api.clone()).await;
	let two = Wire::start(h.api.clone()).await;
	let mut held = Vec::new();
	// Four is the documented per-caller cap, deliberately independent of
	// the private production constant so increasing it breaks this oracle.
	for addr in [one.addr, two.addr, one.addr, two.addr] {
		let (mut stream, reply) = upgrade(addr, ALICE).await;
		assert!(reply.starts_with("HTTP/1.1 101"), "{reply}");
		ping(&mut stream).await;
		held.push(stream);
	}
	for addr in [one.addr, two.addr] {
		let (_, reply) = upgrade(addr, ALICE).await;
		assert!(
			reply.starts_with("HTTP/1.1 429"),
			"caller cap bypassed: {reply}"
		);
	}
	let (mut other, reply) = upgrade(two.addr, ADMIN).await;
	assert!(
		reply.starts_with("HTTP/1.1 101"),
		"another caller was starved: {reply}"
	);
	ping(&mut other).await;
	for stream in &mut held {
		ping(stream).await;
	}
	drop(held.pop());
	// Dropping the peer is asynchronous; retry only the expected temporary
	// 429 under one deadline, then prove the returned slot is usable.
	let mut replacement = timeout(DEADLINE, async {
		loop {
			let (stream, reply) = upgrade(two.addr, ALICE).await;
			if reply.starts_with("HTTP/1.1 101") {
				break stream;
			}
			assert!(reply.starts_with("HTTP/1.1 429"), "{reply}");
			tokio::time::sleep(Duration::from_millis(10)).await;
		}
	})
	.await
	.expect("caller slot was not released");
	ping(&mut replacement).await;
	one.healthy().await;
	two.healthy().await;
}

async fn limited(app: Router) -> (SocketAddr, Abort) {
	let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
	let addr = listener.local_addr().expect("address");
	let task = tokio::spawn(epistle::net::http_serve::serve_with(
		listener,
		app,
		epistle::net::http_serve::Limits {
			connections: 1,
			per_ip: 1,
		},
	));
	(addr, Abort(task.abort_handle()))
}

#[tokio::test]
async fn an_upgraded_socket_holds_the_listener_slot_until_disconnect() {
	let h = Harness::new();
	let (addr, _guard) = limited(h.api.clone()).await;
	let (mut held, reply) = upgrade(addr, ALICE).await;
	assert!(reply.starts_with("HTTP/1.1 101"), "{reply}");
	ping(&mut held).await;
	let (_, reply) = upgrade(addr, ADMIN).await;
	assert!(
		reply.starts_with("HTTP/1.1 503"),
		"upgrade lost admission slot: {reply}"
	);
	ping(&mut held).await;
	drop(held);
	let mut fresh = timeout(DEADLINE, async {
		loop {
			let (stream, reply) = upgrade(addr, ADMIN).await;
			if reply.starts_with("HTTP/1.1 101") {
				break stream;
			}
			assert!(reply.starts_with("HTTP/1.1 503"), "{reply}");
			tokio::time::sleep(Duration::from_millis(10)).await;
		}
	})
	.await
	.expect("listener slot was not released");
	ping(&mut fresh).await;
}
