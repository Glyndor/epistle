//! A request body that trickles, stalls or never ends is cut off; a body
//! that arrives in good time is untouched. Time is paused, so nothing waits.

use std::net::SocketAddr;
use std::time::Duration;

use axum::Router;
use futures_core::Stream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::*;

/// Claimed length of the bodies the tests send; none of it is ever sent.
const CLAIMED: usize = 100_000_000;

/// A handler that drains its body without keeping it and says whether it
/// arrived whole.
async fn serving() -> SocketAddr {
	let router = Router::new().route(
		"/",
		axum::routing::post(|body: Body| async move {
			let mut stream = Box::pin(body.into_data_stream());
			let mut seen = 0usize;
			while let Some(next) = std::future::poll_fn(|cx| stream.as_mut().poll_next(cx)).await {
				match next {
					Ok(chunk) => seen += chunk.len(),
					Err(_) => return (axum::http::StatusCode::REQUEST_TIMEOUT, "slow".to_string()),
				}
			}
			(axum::http::StatusCode::OK, format!("read {seen}"))
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

/// The status line the server answers with, or `None` if it just closed.
async fn answer(stream: &mut TcpStream) -> Option<String> {
	let mut text = Vec::new();
	tokio::time::timeout(Duration::from_secs(3600), stream.read_to_end(&mut text))
		.await
		.expect("the server never answered or closed")
		.ok();
	String::from_utf8_lossy(&text)
		.lines()
		.next()
		.map(str::to_string)
}

#[tokio::test(start_paused = true)]
async fn a_body_that_never_arrives_is_cut_off() {
	let mut stream = post(serving().await, CLAIMED).await;
	let status = answer(&mut stream).await;
	assert!(
		status.is_none_or(|line| line.starts_with("HTTP/1.1 408")),
		"a stalled body kept the connection"
	);
}

#[tokio::test(start_paused = true)]
async fn a_body_that_trickles_is_cut_off() {
	let mut stream = post(serving().await, CLAIMED).await;
	for _ in 0..200 {
		tokio::time::sleep(Duration::from_secs(20)).await;
		if stream.write_all(b"x").await.is_err() {
			return;
		}
	}
	let status = answer(&mut stream).await;
	assert!(
		status.is_none_or(|line| line.starts_with("HTTP/1.1 408")),
		"a trickling body kept the connection"
	);
}

#[tokio::test(start_paused = true)]
async fn a_body_above_the_minimum_rate_still_ends_at_the_deadline() {
	let mut stream = post(serving().await, CLAIMED).await;
	let chunk = vec![b'x'; 2 * BODY_MIN_RATE as usize];
	let started = tokio::time::Instant::now();
	let mut cut = false;
	for _ in 0..(BODY_READ_DEADLINE.as_secs() * 2) {
		tokio::time::sleep(Duration::from_secs(1)).await;
		if stream.write_all(&chunk).await.is_err() {
			cut = true;
			break;
		}
		if started.elapsed() > BODY_READ_DEADLINE + Duration::from_secs(60) {
			break;
		}
	}
	let status = answer(&mut stream).await;
	assert!(
		cut || status.is_none_or(|line| line.starts_with("HTTP/1.1 408")),
		"a body that never ended kept the connection"
	);
	assert!(started.elapsed() <= BODY_READ_DEADLINE + Duration::from_secs(120));
}

#[tokio::test(start_paused = true)]
async fn a_body_that_arrives_in_good_time_is_read() {
	let mut stream = post(serving().await, 11).await;
	tokio::time::sleep(Duration::from_secs(2)).await;
	stream.write_all(b"hello ").await.expect("first");
	tokio::time::sleep(Duration::from_secs(2)).await;
	stream.write_all(b"world").await.expect("second");
	let mut text = Vec::new();
	stream.read_to_end(&mut text).await.expect("answer");
	let text = String::from_utf8_lossy(&text);
	assert!(text.starts_with("HTTP/1.1 200"), "{text}");
	assert!(text.ends_with("read 11"), "{text}");
}

#[tokio::test(start_paused = true)]
async fn a_request_without_a_body_is_not_wrapped() {
	let request = axum::extract::Request::new(Body::empty());
	let request = bound(request, Bounds::default());
	assert!(HttpBody::is_end_stream(request.body()));
}
