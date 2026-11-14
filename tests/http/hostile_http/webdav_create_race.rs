//! Resource existence preconditions must hold at the final write, too.

use std::pin::Pin;
use std::task::{Context, Poll};

use axum::body::{Body, Bytes};
use axum::http::{HeaderValue, StatusCode};
use tokio::sync::mpsc;
use tokio::time::timeout;

use super::harness::{DEADLINE, Harness, call, dav_request};

struct Gated(mpsc::Receiver<Bytes>);

impl futures_core::Stream for Gated {
	type Item = Result<Bytes, std::io::Error>;

	fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
		self.0.poll_recv(cx).map(|chunk| chunk.map(Ok))
	}
}

#[tokio::test]
async fn if_none_match_is_rechecked_after_a_competing_create() {
	// Regression specification: the current refusal helper only checks
	// If-Match. Keep this enabled to expose the missing create-only guard.
	let h = Harness::new();
	let target = h.dav_root("alice").join("new.txt");
	assert!(!target.exists());
	let (sender, receiver) = mpsc::channel::<Bytes>(1);
	let mut slow = dav_request("PUT", "/new.txt", Body::from_stream(Gated(receiver)));
	slow.headers_mut()
		.insert("if-none-match", HeaderValue::from_static("*"));
	let dav = h.dav.clone();
	let slow = tokio::spawn(async move { call(&dav, slow).await });
	// The second send completes only after the handler has consumed a
	// chunk. Its initial precondition check has therefore already passed.
	timeout(DEADLINE, async {
		sender
			.send(Bytes::from_static(b"loser-"))
			.await
			.expect("first chunk");
		sender
			.send(Bytes::from_static(b"body"))
			.await
			.expect("second chunk");
	})
	.await
	.expect("body consumption deadline");
	let mut fast = dav_request("PUT", "/new.txt", Body::from("winner"));
	fast.headers_mut()
		.insert("if-none-match", HeaderValue::from_static("*"));
	let winner = call(&h.dav, fast).await;
	assert_eq!(winner.status, StatusCode::CREATED);
	let winner_etag = winner.headers.get("etag").expect("winner etag").clone();
	drop(sender);
	let loser = timeout(DEADLINE, slow)
		.await
		.expect("slow completion")
		.expect("slow task");
	assert_eq!(loser.status, StatusCode::PRECONDITION_FAILED);
	assert_eq!(std::fs::read(target).expect("winner content"), b"winner");
	let head = call(&h.dav, dav_request("HEAD", "/new.txt", Body::empty())).await;
	assert_eq!(head.status, StatusCode::OK);
	assert_eq!(head.headers.get("etag"), Some(&winner_etag));
	// A refused reservation must also release the account lock.
	h.healthy_dav().await;
}

#[tokio::test]
async fn if_match_star_cannot_resurrect_a_resource_deleted_during_upload() {
	let h = Harness::new();
	let target = h.dav_root("alice").join("gone.txt");
	std::fs::write(&target, b"original").expect("original");
	let (sender, receiver) = mpsc::channel::<Bytes>(1);
	let mut slow = dav_request("PUT", "/gone.txt", Body::from_stream(Gated(receiver)));
	slow.headers_mut()
		.insert("if-match", HeaderValue::from_static("*"));
	let dav = h.dav.clone();
	let slow = tokio::spawn(async move { call(&dav, slow).await });
	timeout(DEADLINE, async {
		sender
			.send(Bytes::from_static(b"resurrected-"))
			.await
			.expect("first chunk");
		sender
			.send(Bytes::from_static(b"body"))
			.await
			.expect("second chunk");
	})
	.await
	.expect("body consumption deadline");
	let removed = call(&h.dav, dav_request("DELETE", "/gone.txt", Body::empty())).await;
	assert_eq!(removed.status, StatusCode::NO_CONTENT);
	assert!(!target.exists());
	drop(sender);
	let reply = timeout(DEADLINE, slow)
		.await
		.expect("slow completion")
		.expect("slow task");
	assert_eq!(reply.status, StatusCode::PRECONDITION_FAILED);
	assert!(
		!target.exists(),
		"a conditional replacement became a create"
	);
	h.healthy_dav().await;
}
