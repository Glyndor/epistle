//! A conditional PUT whose body is still arriving when another client
//! replaces the resource: the precondition was true when the head was read,
//! and must be true again when the file is written.

use std::pin::Pin;
use std::task::{Context, Poll};

use axum::body::{Body, Bytes};
use axum::http::{HeaderValue, StatusCode};
use tokio::sync::mpsc;

use super::harness::{Harness, call, dav_request};

struct Gated(mpsc::Receiver<Bytes>);

impl futures_core::Stream for Gated {
	type Item = Result<Bytes, std::io::Error>;

	fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
		self.0.poll_recv(cx).map(|chunk| chunk.map(Ok))
	}
}

#[tokio::test]
async fn a_put_that_waited_for_its_body_does_not_overwrite_a_newer_version() {
	let h = Harness::new();
	let target = h.dav_root("alice").join("shared.txt");
	std::fs::write(&target, b"original").expect("original");
	let head = call(&h.dav, dav_request("HEAD", "/shared.txt", Body::empty())).await;
	let etag = head.headers.get("etag").expect("etag").clone();

	// A capacity of one makes the second send return only after the handler
	// has taken the first chunk, which it does after it checked If-Match.
	let (sender, receiver) = mpsc::channel::<Bytes>(1);
	let mut slow = dav_request("PUT", "/shared.txt", Body::from_stream(Gated(receiver)));
	slow.headers_mut().insert("if-match", etag.clone());
	let dav = h.dav.clone();
	let slow = tokio::spawn(async move { call(&dav, slow).await });
	sender
		.send(Bytes::from("slow-"))
		.await
		.expect("first chunk");
	sender.send(Bytes::from("one")).await.expect("second chunk");

	let mut fast = dav_request("PUT", "/shared.txt", Body::from("fast"));
	fast.headers_mut().insert(
		"if-match",
		HeaderValue::from_bytes(etag.as_bytes()).expect("tag"),
	);
	assert_eq!(call(&h.dav, fast).await.status, StatusCode::NO_CONTENT);

	drop(sender);
	let reply = slow.await.expect("slow put");
	assert_eq!(
		reply.status,
		StatusCode::PRECONDITION_FAILED,
		"the second writer of one version must lose"
	);
	assert_eq!(std::fs::read(&target).expect("file"), b"fast");
	h.healthy_dav().await;
}
