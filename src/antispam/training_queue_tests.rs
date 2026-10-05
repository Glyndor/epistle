//! Unit tests for the bounded training hand-off queue.
//!
//! The queue exists so a STORE that flips `$Junk` on a whole mailbox
//! does not spawn one task per message. These tests pin the
//! invariants the production path relies on:
//!
//! - the queue is bounded, so a slow worker means the producer drops
//!   jobs rather than blocking the protocol reply;
//! - the drop counter ticks every time the queue is full;
//! - the producer never waits (no `await`, no sleep): the protocol
//!   reply is independent of the worker's pace.

use std::sync::Arc;
use std::time::{Duration, Instant};

use super::{TRAINING_QUEUE_CAPACITY, TrainingJob, TrainingQueue};
use crate::metrics::Metrics;

/// One job's worth of payload, all unique so the trainer would notice
/// duplicates if the queue reordered them.
fn job(n: u32) -> TrainingJob {
	TrainingJob {
		account: format!("acct-{n}"),
		path: std::path::PathBuf::from(format!("/dev/null/job-{n}")),
		spam: n.is_multiple_of(2),
	}
}

/// The 257th job in a steady stream hits a full queue. The producer
/// receives `false` and the dropped counter ticks by one. The receiver
/// stays at the same count it had before the call.
#[test]
fn the_257th_job_is_dropped_and_the_counter_ticks() {
	let metrics = Arc::new(Metrics::new());
	let (queue, mut receiver) = TrainingQueue::bounded(TRAINING_QUEUE_CAPACITY, metrics.clone());
	// Fill the queue: the receiver is held by the test, so no job is
	// ever drained. Capacity is 256; the first 256 submit calls land
	// in the channel.
	for n in 0..TRAINING_QUEUE_CAPACITY {
		assert!(queue.submit(job(n as u32)), "job {n} should fit");
	}
	// The 257th job cannot fit: the queue is full, the producer
	// returns immediately, and the dropped counter reads 1.
	let start = Instant::now();
	let accepted = queue.submit(job(TRAINING_QUEUE_CAPACITY as u32));
	let elapsed = start.elapsed();
	assert!(!accepted, "the 257th job must be dropped");
	assert!(
		elapsed < Duration::from_millis(50),
		"producer must not wait; took {elapsed:?}"
	);
	assert_eq!(
		metrics.snapshot().get("bayes_training_dropped").copied(),
		Some(1),
		"one drop counted"
	);
	// The receiver holds exactly the original 256 jobs; the 257th
	// never made it.
	let mut drained = 0;
	while receiver.try_recv().is_ok() {
		drained += 1;
	}
	assert_eq!(drained, TRAINING_QUEUE_CAPACITY);
}

/// After one drain, the queue accepts jobs again and stops dropping.
#[test]
fn draining_one_slot_lets_the_next_job_through() {
	let metrics = Arc::new(Metrics::new());
	let (queue, mut receiver) = TrainingQueue::bounded(2, metrics.clone());
	assert!(queue.submit(job(1)));
	assert!(queue.submit(job(2)));
	assert!(!queue.submit(job(3)));
	assert_eq!(
		metrics.snapshot().get("bayes_training_dropped").copied(),
		Some(1)
	);
	// Drain one slot.
	let _ = receiver.try_recv().expect("first job");
	assert!(queue.submit(job(4)), "the slot is free, the next job fits");
	assert_eq!(
		metrics.snapshot().get("bayes_training_dropped").copied(),
		Some(1)
	);
}

/// A flood of jobs in a row counts every drop, never blocks the
/// producer, and never exceeds the queue's capacity on the receiver
/// side.
#[test]
fn a_flood_counts_every_drop_and_never_blocks_the_producer() {
	let metrics = Arc::new(Metrics::new());
	let (queue, mut receiver) = TrainingQueue::bounded(TRAINING_QUEUE_CAPACITY, metrics.clone());
	let total = TRAINING_QUEUE_CAPACITY * 4;
	let start = Instant::now();
	let mut accepted = 0;
	for n in 0..total {
		if queue.submit(job(n as u32)) {
			accepted += 1;
		}
	}
	let elapsed = start.elapsed();
	// The producer ran through every call without sleeping: the entire
	// loop wall time is bounded by the cost of `try_send`.
	assert!(
		elapsed < Duration::from_millis(200),
		"a flood of submits must not block; took {elapsed:?}"
	);
	assert_eq!(accepted, TRAINING_QUEUE_CAPACITY);
	assert_eq!(
		metrics.snapshot().get("bayes_training_dropped").copied(),
		Some((total - TRAINING_QUEUE_CAPACITY) as u64),
		"every overflow counted"
	);
	// The receiver only ever sees the first capacity's worth.
	let mut drained = 0;
	while receiver.try_recv().is_ok() {
		drained += 1;
	}
	assert_eq!(drained, TRAINING_QUEUE_CAPACITY);
}
