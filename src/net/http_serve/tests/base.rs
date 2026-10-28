//! What one HTTP client can hold on a plain-HTTP listener: a request head
//! that never finishes, or a keep-alive connection that never sends the
//! next request, is cut off; ordinary requests, the peer address and
//! oversized heads behave as before.

use std::net::SocketAddr;
use std::time::Duration;

use axum::extract::ConnectInfo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::*;

/// Longer than the header timeout, far shorter than forever.
const PATIENCE: Duration = Duration::from_secs(300);

async fn listening() -> SocketAddr {
	let router = Router::new().route(
		"/",
		axum::routing::get(|ConnectInfo(peer): ConnectInfo<SocketAddr>| async move {
			peer.ip().to_string()
		}),
	);
	let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
	let addr = listener.local_addr().expect("addr");
	tokio::spawn(serve(listener, router));
	addr
}

/// Read until the server closes, or `PATIENCE` runs out.
async fn closed_within_patience(stream: &mut TcpStream) -> bool {
	let mut sink = Vec::new();
	tokio::time::timeout(PATIENCE, stream.read_to_end(&mut sink))
		.await
		.is_ok()
}

#[tokio::test(start_paused = true)]
async fn a_request_head_that_never_ends_is_cut_off() {
	let mut stream = TcpStream::connect(listening().await)
		.await
		.expect("connect");
	stream
		.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n")
		.await
		.expect("partial head");
	assert!(
		closed_within_patience(&mut stream).await,
		"a stalled request head kept the connection"
	);
}

#[tokio::test(start_paused = true)]
async fn an_idle_keep_alive_connection_is_cut_off() {
	let mut stream = TcpStream::connect(listening().await)
		.await
		.expect("connect");
	stream
		.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
		.await
		.expect("request");
	let mut response = [0u8; 1024];
	let n = stream.read(&mut response).await.expect("response");
	let text = String::from_utf8_lossy(&response[..n]).to_string();
	assert!(text.starts_with("HTTP/1.1 200"), "{text}");
	assert!(
		text.ends_with("127.0.0.1"),
		"the peer reaches the handler: {text}"
	);
	assert!(
		closed_within_patience(&mut stream).await,
		"an idle keep-alive connection was kept"
	);
}

#[tokio::test]
async fn an_oversized_request_head_is_refused() {
	let mut stream = TcpStream::connect(listening().await)
		.await
		.expect("connect");
	let filler = "a".repeat(1024);
	let mut head = String::from("GET / HTTP/1.1\r\nHost: x\r\n");
	for i in 0..1024 {
		head.push_str(&format!("X-Filler-{i}: {filler}\r\n"));
	}
	head.push_str("\r\n");
	let _ = stream.write_all(head.as_bytes()).await;
	let mut response = Vec::new();
	let _ = stream.read_to_end(&mut response).await;
	let text = String::from_utf8_lossy(&response);
	assert!(
		text.is_empty() || text.starts_with("HTTP/1.1 431"),
		"{}",
		text.lines().next().unwrap_or_default()
	);
}

#[tokio::test(start_paused = true)]
async fn a_websocket_upgrade_reaches_the_handler() {
	use axum::extract::ws::{Message, WebSocketUpgrade};
	let router = Router::new().route(
		"/ws",
		axum::routing::get(|upgrade: WebSocketUpgrade| async move {
			upgrade.on_upgrade(|mut socket| async move {
				let _ = socket.send(Message::Text("hi".into())).await;
			})
		}),
	);
	let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
	let addr = listener.local_addr().expect("addr");
	tokio::spawn(serve(listener, router));
	let mut stream = TcpStream::connect(addr).await.expect("connect");
	stream
		.write_all(
			b"GET /ws HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
			  Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
		)
		.await
		.expect("upgrade request");
	let mut got = Vec::new();
	let mut chunk = [0u8; 512];
	let frame: &[u8] = &[0x81, 0x02, b'h', b'i'];
	let read = tokio::time::timeout(PATIENCE, async {
		while !got.windows(frame.len()).any(|w| w == frame) {
			let n = stream.read(&mut chunk).await.expect("read");
			if n == 0 {
				break;
			}
			got.extend_from_slice(&chunk[..n]);
		}
	})
	.await;
	let text = String::from_utf8_lossy(&got);
	assert!(
		text.starts_with("HTTP/1.1 101"),
		"{}",
		text.lines().next().unwrap_or_default()
	);
	assert!(
		read.is_ok() && got.windows(frame.len()).any(|w| w == frame),
		"the upgraded socket never carried the handler's frame"
	);
}

async fn listening_with(limits: Limits) -> SocketAddr {
	let router = Router::new().route("/", axum::routing::get(|| async { "up" }));
	let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
	let addr = listener.local_addr().expect("addr");
	tokio::spawn(serve_with(listener, router, limits));
	addr
}

#[tokio::test]
async fn a_client_over_its_cap_gets_a_503_and_a_close() {
	use crate::net::conn_limit::test_support::connect;
	let addr = listening_with(Limits {
		connections: 100,
		per_ip: 2,
	})
	.await;
	let first = connect(addr).await;
	let second = connect(addr).await;
	assert!(first.refusal().is_none() && second.refusal().is_none());
	let refused = connect(addr).await;
	let text = refused.refusal().expect("refused");
	assert!(
		text.starts_with("HTTP/1.1 503 Service Unavailable\r\n"),
		"{text}"
	);
	assert!(text.contains("Connection: close\r\n"), "{text}");
}

#[tokio::test]
async fn the_listener_cap_holds_and_a_place_is_given_back() {
	use crate::net::conn_limit::test_support::{connect, connect_when_a_place_frees};
	let addr = listening_with(Limits {
		connections: 1,
		per_ip: 10,
	})
	.await;
	let held = connect(addr).await;
	assert!(held.refusal().is_none());
	assert!(connect(addr).await.refusal().is_some());
	drop(held);
	assert!(connect_when_a_place_frees(addr).await.refusal().is_none());
}

#[tokio::test]
async fn a_served_request_still_works_under_the_limits() {
	let addr = listening_with(Limits {
		connections: 4,
		per_ip: 2,
	})
	.await;
	let mut stream = TcpStream::connect(addr).await.expect("connect");
	stream
		.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
		.await
		.expect("request");
	let mut reply = String::new();
	stream.read_to_string(&mut reply).await.expect("reply");
	assert!(reply.starts_with("HTTP/1.1 200 OK"), "{reply}");
}

/// An upgrade (the JMAP WebSocket) outlives the HTTP exchange; its places in
/// the caps must last as long as the socket does.
mod upgrades {
	use super::*;
	use crate::net::conn_limit::test_support::{connect, connect_when_a_place_frees};
	use axum::extract::ws::{Message, WebSocketUpgrade};

	const UPGRADE: &[u8] = b"GET /ws HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";

	async fn serving(limits: Limits) -> SocketAddr {
		let router = Router::new().route(
			"/ws",
			axum::routing::get(|upgrade: WebSocketUpgrade| async move {
				upgrade.on_upgrade(|mut socket| async move {
					let _ = socket.send(Message::Text("hi".into())).await;
					while socket.recv().await.is_some() {}
				})
			}),
		);
		let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
		let addr = listener.local_addr().expect("addr");
		tokio::spawn(serve_with(listener, router, limits));
		addr
	}

	async fn upgraded(addr: SocketAddr) -> TcpStream {
		let mut stream = TcpStream::connect(addr).await.expect("connect");
		stream.write_all(UPGRADE).await.expect("request");
		let mut buf = [0u8; 512];
		let n = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
			.await
			.expect("answer in time")
			.expect("read");
		let text = String::from_utf8_lossy(&buf[..n]);
		assert!(text.starts_with("HTTP/1.1 101"), "{text}");
		stream
	}

	#[tokio::test]
	async fn live_upgrades_count_against_the_client_cap_and_give_the_place_back() {
		let addr = serving(Limits {
			connections: 100,
			per_ip: 2,
		})
		.await;
		let first = upgraded(addr).await;
		let _second = upgraded(addr).await;
		let third = connect(addr).await;
		assert!(
			third
				.refusal()
				.is_some_and(|text| text.starts_with("HTTP/1.1 503")),
			"a third socket from the same client must be refused while two upgrades live"
		);
		drop(first);
		assert!(connect_when_a_place_frees(addr).await.refusal().is_none());
	}

	#[tokio::test]
	async fn live_upgrades_count_against_the_listener_cap() {
		let addr = serving(Limits {
			connections: 2,
			per_ip: 100,
		})
		.await;
		let _first = upgraded(addr).await;
		let _second = upgraded(addr).await;
		assert!(connect(addr).await.refusal().is_some());
	}
}
