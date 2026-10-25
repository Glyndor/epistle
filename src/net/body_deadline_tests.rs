//! A request body that trickles, stalls or never ends is cut off; a body
//! that arrives in good time is untouched, however long the handler took to
//! start reading it. Time is paused, so nothing waits.

use std::net::SocketAddr;
use std::time::Duration;

use axum::Router;
use futures_core::Stream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Instant;

use super::*;

/// Claimed length of the bodies the tests send; little of it is ever sent.
const CLAIMED: usize = 100_000_000;

/// A handler that waits `delay`, drains its body without keeping it, and
/// says whether it arrived whole.
async fn serving(delay: Duration) -> SocketAddr {
	let router = Router::new()
		.route(
			"/",
			axum::routing::post(move |body: Body| async move {
				tokio::time::sleep(delay).await;
				let mut stream = Box::pin(body.into_data_stream());
				let mut seen = 0usize;
				while let Some(next) =
					std::future::poll_fn(|cx| stream.as_mut().poll_next(cx)).await
				{
					match next {
						Ok(chunk) => seen += chunk.len(),
						Err(_) => {
							return (axum::http::StatusCode::REQUEST_TIMEOUT, "slow".to_string());
						}
					}
				}
				(axum::http::StatusCode::OK, format!("read {seen}"))
			}),
		)
		.route("/", axum::routing::get(|| async { "got" }))
		.route(
			"/ws",
			axum::routing::get(|upgrade: axum::extract::ws::WebSocketUpgrade| async move {
				upgrade.on_upgrade(|_| async {})
			}),
		);
	let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
	let addr = listener.local_addr().expect("addr");
	tokio::spawn(crate::net::http_serve::serve(listener, router));
	addr
}

async fn post(addr: SocketAddr, claimed: usize) -> TcpStream {
	let mut stream = TcpStream::connect(addr).await.expect("connect");
	let head = format!(
		"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: {claimed}\r\nConnection: close\r\n\r\n"
	);
	stream.write_all(head.as_bytes()).await.expect("head");
	stream
}

/// Everything the server sends until it closes.
async fn answer(stream: &mut TcpStream) -> String {
	let mut text = Vec::new();
	tokio::time::timeout(Duration::from_secs(10_000), stream.read_to_end(&mut text))
		.await
		.expect("the server never answered or closed")
		.ok();
	String::from_utf8_lossy(&text).to_string()
}

/// Send `chunk` every `every` until the server closes; how long that took
/// and what the server said.
async fn send_steadily(claimed: usize, chunk: usize, every: Duration) -> (Duration, String) {
	let stream = post(serving(Duration::ZERO).await, claimed).await;
	let (mut read, mut write) = stream.into_split();
	let sender = tokio::spawn(async move {
		let data = vec![b'x'; chunk];
		loop {
			tokio::time::sleep(every).await;
			if write.write_all(&data).await.is_err() {
				break;
			}
		}
	});
	let started = Instant::now();
	let mut text = Vec::new();
	tokio::time::timeout(Duration::from_secs(10_000), read.read_to_end(&mut text))
		.await
		.expect("the server never closed")
		.ok();
	sender.abort();
	(
		started.elapsed(),
		String::from_utf8_lossy(&text).to_string(),
	)
}

fn cut(text: &str) -> bool {
	text.is_empty() || text.starts_with("HTTP/1.1 408")
}

#[tokio::test(start_paused = true)]
async fn a_body_that_never_arrives_is_cut_off() {
	let mut stream = post(serving(Duration::ZERO).await, CLAIMED).await;
	let text = answer(&mut stream).await;
	assert!(cut(&text), "a stalled body kept the connection: {text}");
}

#[tokio::test(start_paused = true)]
async fn a_body_below_the_minimum_rate_is_cut_off_by_the_rate() {
	// 20 octets per second for as long as the server allows: far below the
	// minimum rate, and cut long before any deadline.
	let (took, text) = send_steadily(CLAIMED, 100, Duration::from_secs(5)).await;
	assert!(cut(&text), "{text}");
	assert!(
		took < Duration::from_secs(120),
		"cut after {took:?}, not by the rate"
	);
}

#[tokio::test(start_paused = true)]
async fn a_body_above_the_minimum_rate_still_ends_at_the_deadline() {
	let (took, text) =
		send_steadily(CLAIMED, 2 * BODY_MIN_RATE as usize, Duration::from_secs(1)).await;
	assert!(cut(&text), "{text}");
	assert!(
		took >= BODY_DEADLINE_CEILING - Duration::from_secs(5)
			&& took <= BODY_DEADLINE_CEILING + Duration::from_secs(60),
		"cut after {took:?}, not at the ceiling"
	);
}

#[tokio::test(start_paused = true)]
async fn a_body_just_above_the_minimum_rate_is_read() {
	let total = 60 * 2 * BODY_MIN_RATE as usize;
	let mut stream = post(serving(Duration::ZERO).await, total).await;
	let chunk = vec![b'x'; 2 * BODY_MIN_RATE as usize];
	for _ in 0..60 {
		tokio::time::sleep(Duration::from_secs(1)).await;
		stream.write_all(&chunk).await.expect("chunk");
	}
	let text = answer(&mut stream).await;
	assert!(text.starts_with("HTTP/1.1 200"), "{text}");
	assert!(text.ends_with(&format!("read {total}")), "{text}");
}

#[tokio::test(start_paused = true)]
async fn a_slow_upload_of_a_large_body_gets_time_in_proportion() {
	// 4 MiB at 3 KiB/s takes 1365 s: past the base deadline, within the
	// time the declared length earns.
	let total = 4 * 1024 * 1024;
	let step = 3 * 1024;
	let mut stream = post(serving(Duration::ZERO).await, total).await;
	let mut sent = 0;
	while sent < total {
		let n = step.min(total - sent);
		tokio::time::sleep(Duration::from_secs(1)).await;
		stream.write_all(&vec![b'x'; n]).await.expect("chunk");
		sent += n;
	}
	let text = answer(&mut stream).await;
	assert!(text.starts_with("HTTP/1.1 200"), "{text}");
}

#[tokio::test(start_paused = true)]
async fn the_clock_starts_when_the_handler_reads() {
	// The handler only starts reading after longer than the grace, and the
	// body arrives a few seconds after that.
	let mut stream = post(serving(Duration::from_secs(30)).await, 5).await;
	tokio::time::sleep(Duration::from_secs(35)).await;
	stream.write_all(b"hello").await.expect("body");
	let text = answer(&mut stream).await;
	assert!(text.starts_with("HTTP/1.1 200"), "{text}");
	assert!(text.ends_with("read 5"), "{text}");
}

#[test]
fn the_deadline_follows_the_declared_length_between_its_bounds() {
	let bounds = Bounds::default();
	assert_eq!(bounds.deadline_for(None), BODY_READ_DEADLINE);
	assert_eq!(bounds.deadline_for(Some(10)), BODY_READ_DEADLINE);
	assert_eq!(
		bounds.deadline_for(Some(2 * 1024 * 1024)),
		Duration::from_secs(2048)
	);
	assert_eq!(
		bounds.deadline_for(Some(25 * 1024 * 1024)),
		BODY_DEADLINE_CEILING
	);
}

#[tokio::test(start_paused = true)]
async fn a_get_is_served_untouched() {
	let mut stream = TcpStream::connect(serving(Duration::ZERO).await)
		.await
		.expect("connect");
	stream
		.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
		.await
		.expect("request");
	let text = answer(&mut stream).await;
	assert!(text.starts_with("HTTP/1.1 200"), "{text}");
	assert!(text.ends_with("got"), "{text}");
}

#[tokio::test(start_paused = true)]
async fn a_websocket_upgrade_still_goes_through() {
	let mut stream = TcpStream::connect(serving(Duration::ZERO).await)
		.await
		.expect("connect");
	stream
		.write_all(
			b"GET /ws HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
			  Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
		)
		.await
		.expect("upgrade request");
	let mut head = [0u8; 12];
	stream.read_exact(&mut head).await.expect("status line");
	assert_eq!(&head, b"HTTP/1.1 101");
}

#[tokio::test(start_paused = true)]
async fn a_request_without_a_body_is_not_wrapped() {
	let request = axum::extract::Request::new(Body::empty());
	let request = bound(request, Bounds::default());
	assert!(HttpBody::is_end_stream(request.body()));
}
