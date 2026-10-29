use super::{Failed, is_lock_contention, run};
use std::time::Duration;

fn failing(transient: bool, message: &str) -> Result<(), Failed> {
	Err(Failed {
		message: message.to_string(),
		transient,
	})
}

#[test]
fn a_lock_held_for_two_attempts_does_not_stop_the_move() {
	let mut calls = 0;
	let result = run(5, Duration::ZERO, || {
		calls += 1;
		if calls <= 2 {
			failing(true, "locked")
		} else {
			Ok(())
		}
	});
	assert_eq!(result, Ok(()));
	assert_eq!(calls, 3, "the third attempt is the first to find it free");
}

#[test]
fn a_lock_that_never_clears_is_reported_after_the_last_attempt() {
	let mut calls = 0;
	let result = run(5, Duration::ZERO, || {
		calls += 1;
		failing(true, "still locked")
	});
	assert_eq!(result, Err("still locked".to_string()));
	assert_eq!(calls, 5, "bounded: five attempts, not an endless wait");
}

#[test]
fn a_permanent_failure_is_not_asked_again() {
	let mut calls = 0;
	let result = run(5, Duration::ZERO, || {
		calls += 1;
		failing(false, "no such user")
	});
	assert_eq!(result, Err("no such user".to_string()));
	assert_eq!(calls, 1);
}

#[test]
fn the_messages_usermod_prints_for_a_held_lock_are_recognised() {
	for text in [
		"usermod: cannot lock /etc/subuid; try again later.\n",
		"usermod: Unable to lock /etc/subgid\n",
		"CANNOT LOCK /etc/passwd",
	] {
		assert!(is_lock_contention(text), "{text}");
	}
	for text in [
		"usermod: user 'glyndor-epistle' does not exist\n",
		"usermod: invalid subordinate uid range '1-0'\n",
		"",
	] {
		assert!(!is_lock_contention(text), "{text}");
	}
}
