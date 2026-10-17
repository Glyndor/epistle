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

use super::{
	MAX_TRAINING_BYTES, TRAINING_QUEUE_CAPACITY, TrainingJob, TrainingQueue, training_window,
};
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

/// A message over the window is trained on its start and its end, so
/// filler in front of the part that matters does not hide it.
#[test]
fn the_window_of_a_long_message_is_its_start_and_its_end() {
	let mut message = vec![b'x'; 3 * MAX_TRAINING_BYTES];
	message[..6].copy_from_slice(b"HEADER");
	let middle = message.len() / 2;
	message[middle..middle + 6].copy_from_slice(b"MIDDLE");
	let end = message.len();
	message[end - 4..].copy_from_slice(b"TAIL");
	let window = training_window(&message);
	assert_eq!(window.len(), MAX_TRAINING_BYTES);
	assert!(window.starts_with(b"HEADER") && window.ends_with(b"TAIL"));
	assert!(!window.windows(6).any(|part| part == b"MIDDLE"));
}

#[test]
fn a_message_that_fits_is_trained_whole() {
	let message = vec![b'x'; MAX_TRAINING_BYTES];
	assert!(matches!(
		training_window(&message),
		std::borrow::Cow::Borrowed(_)
	));
	assert_eq!(training_window(b"short").as_ref(), b"short");
	assert!(training_window(b"").is_empty());
}

/// The seams of the window never leave half a word behind: a word cut by
/// the window would become a token nobody wrote.
#[test]
fn the_window_does_not_cut_a_word_at_its_seams() {
	for shift in 0..12 {
		let mut message = "x".repeat(shift).into_bytes();
		message.extend_from_slice(&"wordy ".repeat(3 * MAX_TRAINING_BYTES / 6).into_bytes());
		let window = training_window(&message);
		assert!(window.len() <= MAX_TRAINING_BYTES);
		let text = String::from_utf8(window.into_owned()).expect("utf-8");
		for token in text.split(|c: char| !c.is_alphanumeric()) {
			assert!(
				token.is_empty()
					|| token == "wordy"
					|| token.starts_with("xwordy")
					|| token.chars().all(|c| c == 'x')
					|| token.ends_with("wordy"),
				"a fragment {token:?} appeared at a seam"
			);
		}
	}
}
