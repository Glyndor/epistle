//! One test per minute per server, checked and recorded under one lock.

use std::sync::mpsc;
use std::time::Duration;

use crate::cli::deliverability::guard::{Guard, MIN_INTERVAL_SECS};

const T: u64 = 1_800_000_000;

#[test]
fn the_second_run_inside_a_minute_is_refused_and_told_when_it_may_run() {
	let dir = tempfile::tempdir().expect("dir");
	Guard::acquire(dir.path(), T)
		.expect("first")
		.record(T)
		.expect("record");
	let refusal = Guard::acquire(dir.path(), T + MIN_INTERVAL_SECS - 1)
		.err()
		.expect("refused");
	assert_eq!(refusal.code, 3);
	assert!(refusal.message.contains("in 1 s"), "{}", refusal.message);
	Guard::acquire(dir.path(), T + MIN_INTERVAL_SECS).expect("a minute later");
}

#[test]
fn a_run_that_never_recorded_spends_nothing() {
	let dir = tempfile::tempdir().expect("dir");
	drop(Guard::acquire(dir.path(), T).expect("first"));
	Guard::acquire(dir.path(), T).expect("nothing was recorded");
}

#[test]
fn two_runs_that_start_together_cannot_both_pass() {
	let dir = tempfile::tempdir().expect("dir");
	let first = Guard::acquire(dir.path(), T).expect("first");
	let (ready, waiting) = mpsc::channel();
	let path = dir.path().to_path_buf();
	let second = std::thread::spawn(move || {
		ready.send(()).expect("signal");
		Guard::acquire(&path, T).err().map(|refusal| refusal.code)
	});
	waiting.recv().expect("started");
	std::thread::sleep(Duration::from_millis(200));
	first.record(T).expect("record");
	assert_eq!(second.join().expect("join"), Some(3));
}

#[test]
fn a_last_run_in_the_future_does_not_block_for_ever() {
	let dir = tempfile::tempdir().expect("dir");
	Guard::acquire(dir.path(), T + 100_000)
		.expect("first")
		.record(T + 100_000)
		.expect("record");
	Guard::acquire(dir.path(), T).expect("the clock went back");
}

#[test]
fn a_state_file_that_cannot_be_read_stops_the_run() {
	let dir = tempfile::tempdir().expect("dir");
	std::fs::write(dir.path().join("deliverability-test.json"), "not json").expect("write");
	let refusal = Guard::acquire(dir.path(), T).err().expect("refused");
	assert_eq!(refusal.code, 1);
}
