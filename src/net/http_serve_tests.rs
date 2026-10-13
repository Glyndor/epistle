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
