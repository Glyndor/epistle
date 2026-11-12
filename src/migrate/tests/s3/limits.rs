//! An endpoint that lies about a length, stalls, redirects or pages forever
//! must cost one failed call: an error, little memory, and a bounded wait.

use super::DEADLINE;
use super::raw::{Script, start};
use crate::storage::blob_backend::S3Limits as Limits;
use crate::storage::{BlobAccount, BlobBackend, BlobError};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

const CAP: u64 = 4096;

fn limits() -> Limits {
	Limits {
		connect: Duration::from_secs(1),
		read: Duration::from_millis(600),
		total: Duration::from_millis(1500),
		object: CAP,
		listing: CAP,
		pages: 5,
		keys: 3,
	}
}

fn account() -> BlobAccount {
	BlobAccount::new("alice").expect("alice")
}

fn id() -> uuid::Uuid {
	uuid::Uuid::parse_str("0198f2c1-9a4b-7000-8000-0000000000aa").expect("id")
}

/// The error text of a refusal; fails when the call succeeded or died of
/// anything but a remote-peer error.
fn refusal<T: std::fmt::Debug>(result: Result<T, BlobError>) -> String {
	match result {
		Err(BlobError::Remote(text)) => text,
		other => panic!("expected a remote error, got {other:?}"),
	}
}

/// Fetch one object on a current-thread runtime, so the allocation probe sees
/// the client, the fake and the buffers between them on one thread.
fn get_measured(script: Script) -> (Result<Option<Vec<u8>>, BlobError>, usize) {
	let runtime = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()
		.expect("runtime");
	crate::sieve::test_peak_bytes(|| {
		runtime.block_on(async {
			let (backend, _requests, _peer) = start(script, limits()).await;
			tokio::time::timeout(DEADLINE, backend.get(&account(), id(), ""))
				.await
				.expect("GetObject deadline")
		})
	})
}

#[test]
fn body_declaring_four_gib_is_refused_before_reading_it() {
	let (result, peak) = get_measured(Script::Declared {
		length: 4 << 30,
		sent: 3,
	});
	assert!(refusal(result).contains("byte limit"));
	assert!(peak < 1024 * 1024, "reserved {peak} bytes for a header");
}

#[test]
fn body_with_no_declared_length_is_stopped_at_the_cap() {
	// 8 MiB are on their way; the cap lets 4 KiB through.
	let (result, peak) = get_measured(Script::Chunked { chunks: 128 });
	assert!(refusal(result).contains("byte limit"));
	assert!(peak < 2 * 1024 * 1024, "held {peak} bytes");
}

/// Positive control for the two above: a body of exactly the cap is read.
#[test]
fn body_exactly_at_the_cap_is_returned() {
	let (result, _) = get_measured(Script::Declared {
		length: CAP,
		sent: CAP as usize,
	});
	assert_eq!(
		result.expect("a body at the cap"),
		Some(vec![7; CAP as usize])
	);
}

#[test]
fn body_one_byte_over_the_cap_is_refused() {
	let (result, _) = get_measured(Script::Declared {
		length: CAP + 1,
		sent: CAP as usize + 1,
	});
	assert!(refusal(result).contains("byte limit"));
}

#[tokio::test]
async fn endpoint_that_never_answers_times_out() {
	let (backend, requests, _peer) = start(Script::Silent, limits()).await;
	let started = Instant::now();
	let result = tokio::time::timeout(DEADLINE, backend.get(&account(), id(), ""))
		.await
		.expect("GetObject exceeded the deadline");
	refusal(result);
	assert_eq!(requests.load(Ordering::SeqCst), 1);
	assert!(started.elapsed() < DEADLINE);
}

#[tokio::test]
async fn body_trickled_to_beat_the_read_timeout_is_cut_by_the_total_one() {
	let (backend, _requests, _peer) = start(Script::Trickle, limits()).await;
	let started = Instant::now();
	let result = tokio::time::timeout(DEADLINE, backend.get(&account(), id(), ""))
		.await
		.expect("GetObject exceeded the deadline");
	refusal(result);
	assert!(started.elapsed() < DEADLINE);
}

#[tokio::test]
async fn redirect_loop_is_an_error_and_is_not_followed() {
	for request in 0..2 {
		let (backend, requests, _peer) = start(Script::Redirect, limits()).await;
		let result = if request == 0 {
			tokio::time::timeout(DEADLINE, backend.get(&account(), id(), "")).await
		} else {
			tokio::time::timeout(DEADLINE, async { backend.list().await.map(|_| None) }).await
		};
		let text = refusal(result.expect("redirect deadline"));
		assert!(text.contains("302"), "{text}");
		assert_eq!(requests.load(Ordering::SeqCst), 1, "redirect was followed");
	}
}

#[tokio::test]
async fn listing_that_repeats_its_token_is_refused() {
	let (backend, requests, _peer) = start(
		Script::Pages {
			keys: 1,
			same_token: true,
			last: None,
		},
		limits(),
	)
	.await;
	let result = tokio::time::timeout(DEADLINE, backend.list())
		.await
		.expect("listing exceeded the deadline");
	assert!(refusal(result).contains("repeats its continuation token"));
	assert_eq!(requests.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn listing_that_never_ends_is_cut_at_the_page_cap() {
	let (backend, requests, _peer) = start(
		Script::Pages {
			keys: 0,
			same_token: false,
			last: None,
		},
		limits(),
	)
	.await;
	let result = tokio::time::timeout(DEADLINE, backend.list())
		.await
		.expect("listing exceeded the deadline");
	assert!(refusal(result).contains("longer than 5 pages"));
	assert_eq!(requests.load(Ordering::SeqCst), 5);
}

#[tokio::test]
async fn listing_with_more_objects_than_the_cap_is_refused() {
	let (backend, _requests, _peer) = start(
		Script::Pages {
			keys: 2,
			same_token: false,
			last: Some(2),
		},
		limits(),
	)
	.await;
	let result = tokio::time::timeout(DEADLINE, backend.list())
		.await
		.expect("listing exceeded the deadline");
	assert!(refusal(result).contains("more than 3 objects"));
}

/// Positive control for the three listing refusals: pages that end inside
/// every cap are read to the end.
#[tokio::test]
async fn listing_inside_every_cap_is_read_to_the_end() {
	let (backend, requests, _peer) = start(
		Script::Pages {
			keys: 1,
			same_token: false,
			last: Some(3),
		},
		limits(),
	)
	.await;
	let ids = tokio::time::timeout(DEADLINE, backend.list())
		.await
		.expect("listing exceeded the deadline")
		.expect("a listing inside the caps");
	assert_eq!(ids.len(), 3);
	assert_eq!(requests.load(Ordering::SeqCst), 3);
}
