use std::process::Command;
use std::time::{Duration, Instant};

use super::output_until;

#[test]
fn a_program_that_finishes_gives_its_output_and_status() {
	let (status, stdout) = output_until(
		Command::new("sh").args(["-c", "printf hello"]),
		Instant::now() + Duration::from_secs(10),
	)
	.expect("runs");
	assert!(status.success());
	assert_eq!(stdout, b"hello");
}

#[test]
fn a_program_with_more_output_than_a_pipe_holds_is_not_taken_for_a_hang() {
	let (status, stdout) = output_until(
		Command::new("sh").args(["-c", "head -c 300000 /dev/zero | tr '\\0' x"]),
		Instant::now() + Duration::from_secs(20),
	)
	.expect("runs");
	assert!(status.success());
	assert_eq!(stdout.len(), 300_000);
}

/// A program past its time is killed, and the call returns at that time and
/// not when the program would have finished.
#[test]
fn a_program_still_running_at_the_deadline_is_killed() {
	let started = Instant::now();
	let marker = tempfile::tempdir().expect("dir");
	let file = marker.path().join("survived");
	let script = format!("sleep 30; touch {}", file.display());
	let error = output_until(
		Command::new("sh").args(["-c", &script]),
		Instant::now() + Duration::from_millis(300),
	)
	.expect_err("killed");
	assert!(error.contains("over"), "{error}");
	assert!(
		started.elapsed() < Duration::from_secs(10),
		"{:?}",
		started.elapsed()
	);
	assert!(!file.exists());
}

#[test]
fn nothing_is_started_once_the_time_is_over() {
	let marker = tempfile::tempdir().expect("dir");
	let file = marker.path().join("ran");
	let script = format!("touch {}", file.display());
	let error = output_until(
		Command::new("sh").args(["-c", &script]),
		Instant::now() - Duration::from_secs(1),
	)
	.expect_err("late");
	assert!(error.contains("over"), "{error}");
	assert!(!file.exists());
}

/// A program that ends but leaves something running in its group that holds
/// the output open does not hang the collection: the group goes with it.
#[test]
fn a_grandchild_in_the_group_does_not_hold_the_output_open() {
	let started = Instant::now();
	let (status, stdout) = output_until(
		Command::new("sh").args(["-c", "sleep 30 & echo hi"]),
		Instant::now() + Duration::from_secs(20),
	)
	.expect("runs");
	assert!(status.success());
	assert_eq!(stdout, b"hi\n");
	assert!(
		started.elapsed() < Duration::from_secs(10),
		"{:?}",
		started.elapsed()
	);
}

/// Something the program started in a group of its own, holding the output
/// open, is waited for no longer than the time of the check: the call returns at
/// that time with an error.
#[test]
fn a_process_outside_the_group_that_holds_the_output_is_not_waited_for() {
	let started = Instant::now();
	let error = output_until(
		Command::new("sh").args(["-c", "setsid sleep 6 & echo hi"]),
		Instant::now() + Duration::from_millis(500),
	)
	.expect_err("the output never ends");
	assert!(error.contains("over"), "{error}");
	assert!(
		started.elapsed() < Duration::from_secs(4),
		"{:?}",
		started.elapsed()
	);
}

/// Output past the most that is kept is dropped, and the program is not
/// stopped by a pipe nobody empties.
#[test]
fn an_enormous_output_is_cut_and_the_program_still_finishes() {
	let (status, stdout) = output_until(
		Command::new("sh").args(["-c", "head -c 20000000 /dev/zero | tr '\\0' x"]),
		Instant::now() + Duration::from_secs(60),
	)
	.expect("runs");
	assert!(status.success());
	assert_eq!(stdout.len() as u64, super::MAX_OUTPUT);
}
