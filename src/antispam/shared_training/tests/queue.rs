//! Tests for the bounded queue and the refunds.

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use super::base::alone;
use super::*;
use crate::antispam::training_queue::MAX_TRAINING_BYTES;

#[test]
fn a_full_queue_drops_the_job_and_gives_the_share_back() {
	let (queue, _receiver, budget) = SharedTraining::bounded(2);
	let now = Instant::now();
	let data = b"some text";
	assert_eq!(queue.try_submit(now, &alone(1), "", data, true), Ok(()));
	assert_eq!(queue.try_submit(now, &alone(2), "", data, true), Ok(()));
	assert_eq!(
		queue.try_submit(now, &alone(3), "", data, true),
		Err(Refusal::QueueFull)
	);
	assert_eq!(budget.pending(&alone(3), true), 0);
	assert_eq!(budget.pending(&alone(1), true), 1);
}

#[test]
fn one_source_cannot_fill_the_queue_for_the_rest() {
	let (queue, _receiver, _budget) = SharedTraining::bounded(QUEUE_CAPACITY);
	let now = Instant::now();
	let accepted = (0..200)
		.filter(|_| queue.try_submit(now, &alone(1), "", b"x", true).is_ok())
		.count();
	assert_eq!(accepted, FINE_PENDING as usize);
	assert_eq!(queue.try_submit(now, &alone(2), "", b"x", false), Ok(()));
}

#[test]
fn without_a_source_the_small_network_of_its_own_bounds_the_job() {
	let (queue, _receiver, _budget) = SharedTraining::bounded(10);
	let now = Instant::now();
	let accepted = (0..50)
		.filter(|_| {
			queue
				.try_submit(now, &TrainSource::unattributed(), "", b"x", true)
				.is_ok()
		})
		.count();
	assert_eq!(accepted, UNATTRIBUTED_PENDING as usize);
}

#[tokio::test]
async fn a_job_keeps_only_the_window_of_a_huge_message() {
	let (queue, mut receiver, _budget) = SharedTraining::bounded(4);
	let body: String = (0..60_000).map(|n| format!("wd{n:07x} ")).collect();
	let huge = format!("Subject: x\r\n\r\nstartword {body}endword\r\n");
	assert!(queue.submit(&alone(1), "scope", huge.as_bytes(), true));
	let job = receiver.recv().await.expect("queued job");
	assert!(job.text.len() <= MAX_TRAINING_BYTES);
	assert!(
		job.text.len() > MAX_TRAINING_BYTES - 1024,
		"the window was not filled"
	);
	let text = String::from_utf8(job.text).expect("tokens are text");
	assert!(text.starts_with("Subject startword") && text.trim_end().ends_with("endword"));
	assert_eq!(job.scope, "scope");
	assert!(job.spam);
}

/// An attachment is not part of what the corpus learns from.
#[tokio::test]
async fn a_job_does_not_carry_the_attachments_of_the_message() {
	let (queue, mut receiver, _budget) = SharedTraining::bounded(4);
	let raw = format!(
		"Subject: x\r\nContent-Type: multipart/mixed; boundary=\"b\"\r\n\r\n--b\r\n\
		 Content-Type: text/plain\r\n\r\nhello world\r\n--b\r\n\
		 Content-Type: application/pdf\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n--b--\r\n",
		"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=\n".repeat(20_000)
	);
	assert!(queue.submit(&alone(1), "", raw.as_bytes(), false));
	let job = receiver.recv().await.expect("queued job");
	assert!(
		job.text.len() < 200,
		"the job carried {} bytes",
		job.text.len()
	);
}

#[tokio::test]
async fn submitting_never_waits_even_with_nobody_draining() {
	let (queue, _receiver, _budget) = SharedTraining::bounded(1);
	// A current-thread runtime with no other task: a `submit` that waited
	// for room would hang this test.
	for n in 0..50 {
		let _ = queue.submit(&alone(n), "", b"x", true);
	}
}

#[tokio::test]
async fn the_workers_give_the_share_back_when_a_job_is_done() {
	// A pool that cannot connect: every training fails at once, which is
	// all this test needs, the share must come back either way.
	let pool = sqlx::postgres::PgPoolOptions::new()
		.acquire_timeout(Duration::from_millis(200))
		.connect_lazy("postgres://nobody@127.0.0.1:1/none")
		.expect("lazy pool");
	let store = BayesStore::with_key(pool, [3u8; 32]);
	let queue = SharedTraining::start(store);
	let s = alone(9);
	for _ in 0..FINE_PENDING {
		assert!(queue.submit(&s, "scope", b"text here", true));
	}
	assert!(!queue.submit(&s, "scope", b"text here", true));
	let mut served = false;
	for _ in 0..100 {
		tokio::time::sleep(Duration::from_millis(100)).await;
		if queue.submit(&s, "scope", b"text here", true) {
			served = true;
			break;
		}
	}
	assert!(served, "the workers never finished the jobs of the source");
}

/// A message that could not be read teaches nothing and costs its source
/// nothing: no place in the queue, no share of the window, no job pending.
#[tokio::test]
async fn a_message_that_could_not_be_read_is_not_queued_or_charged() {
	let (queue, mut receiver, budget) = SharedTraining::bounded(4);
	let s = alone(5);
	for _ in 0..(FINE_PER_WINDOW + 3) {
		crate::antispam::scoring_text::fail_next_reduction();
		assert_eq!(
			queue.try_submit(Instant::now(), &s, "scope", b"text here", true),
			Err(Refusal::Unread)
		);
	}
	assert!(receiver.try_recv().is_err(), "an unread message was queued");
	assert_eq!(budget.pending(&s, true), 0);
	for _ in 0..FINE_PENDING {
		assert_eq!(
			queue.try_submit(Instant::now(), &s, "scope", b"text here", true),
			Ok(()),
			"the failures were charged to the source"
		);
		let _ = receiver.try_recv();
		budget.release(&s, true);
	}
	// Nor is the whole server charged: many sources failing together would
	// otherwise use up the global share of the window.
	for n in 0..=255u8 {
		for _ in 0..10 {
			crate::antispam::scoring_text::fail_next_reduction();
			let _ = queue.try_submit(Instant::now(), &alone(n), "scope", b"text", false);
		}
	}
	assert_eq!(
		queue.try_submit(Instant::now(), &alone(77), "scope", b"text here", false),
		Ok(())
	);
}

/// Every key a job was charged to gets its share back, not only the finest
/// address: the domain, the wider block and the network.
#[tokio::test]
async fn a_refund_reaches_every_key_the_job_was_charged_to() {
	let ip = |a: u8, b: u8, c: u8, d: u8| Some(IpAddr::V4(Ipv4Addr::new(a, b, c, d)));
	// (what the sources share, how many jobs it takes to fill it, the sources)
	let mut cases: Vec<(&str, Vec<TrainSource>)> = Vec::new();
	cases.push((
		"domain",
		(0..=255u8)
			.map(|n| TrainSource::new(ip(10, n, 0, 1), Some("example.org")))
			.collect(),
	));
	cases.push((
		"block",
		(1..=250u8)
			.map(|n| TrainSource::new(ip(10, 1, 1, n), None))
			.collect(),
	));
	cases.push((
		"network",
		(0..=250u8)
			.map(|n| TrainSource::new(ip(10, 2, n, 1), None))
			.collect(),
	));
	for (name, sources) in cases {
		let (queue, mut receiver, budget) = SharedTraining::bounded(4);
		for round in 0..(BLOCK_PER_WINDOW as usize + 20) {
			crate::antispam::scoring_text::fail_next_reduction();
			let source = &sources[round % sources.len()];
			assert_eq!(
				queue.try_submit(Instant::now(), source, "scope", b"text", true),
				Err(Refusal::Unread),
				"{name}: the unread jobs were charged (round {round})"
			);
		}
		assert!(receiver.try_recv().is_err());
		assert_eq!(budget.pending(&sources[0], true), 0, "{name}");
	}
}

/// A refund gives back what one job was charged and no more: after it, the
/// source can still be admitted exactly as often as before.
#[test]
fn a_refund_gives_back_one_job_and_no_more() {
	let budget = Budget::default();
	let s = alone(3);
	let now = Instant::now();
	// One job that did run is counted, whatever is refunded after it.
	budget.admit(now, &s, true).expect("admitted");
	budget.release(&s, true);
	let charge = budget.admit_charged(now, &s, true).expect("admitted");
	budget.refund(charge);
	let mut admitted = 0;
	while budget.admit(now, &s, true).is_ok() {
		budget.release(&s, true);
		admitted += 1;
	}
	assert_eq!(admitted, FINE_PER_WINDOW as usize - 1);
}
