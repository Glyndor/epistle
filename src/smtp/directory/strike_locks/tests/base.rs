use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::time::Duration;

use super::StrikeLocks;

fn subjects(names: &[&str]) -> Vec<String> {
	names.iter().map(|n| (*n).to_string()).collect()
}

#[test]
fn sign_ins_sharing_a_subject_run_one_at_a_time() {
	let locks = Arc::new(StrikeLocks::new(64, usize::MAX));
	let inside = Arc::new(AtomicUsize::new(0));
	let most = Arc::new(AtomicUsize::new(0));
	let start = Arc::new(Barrier::new(8));
	let threads: Vec<_> = (0..8)
		.map(|n| {
			let (locks, inside, most, start) =
				(locks.clone(), inside.clone(), most.clone(), start.clone());
			std::thread::spawn(move || {
				start.wait();
				// Every sign-in shares the account; the clients differ.
				let held = locks
					.hold(&subjects(&[&format!("ip:10.0.0.{n}"), "account:alice"]))
					.expect("no limit");
				let now = inside.fetch_add(1, Ordering::SeqCst) + 1;
				most.fetch_max(now, Ordering::SeqCst);
				std::thread::sleep(Duration::from_millis(10));
				inside.fetch_sub(1, Ordering::SeqCst);
				drop(held);
			})
		})
		.collect();
	for thread in threads {
		thread.join().expect("thread");
	}
	assert_eq!(most.load(Ordering::SeqCst), 1);
}

#[test]
fn subjects_on_one_stripe_are_taken_once() {
	let locks = StrikeLocks::new(1, usize::MAX);
	let held = locks
		.hold(&subjects(&["ip:1.1.1.1", "pair:a|1.1.1.1", "account:a"]))
		.expect("one stripe, taken once");
	assert_eq!(held.len(), 1);
}

#[test]
fn a_full_line_turns_the_sign_in_away_without_waiting() {
	let locks = Arc::new(StrikeLocks::new(1, 1));
	let first = locks.hold(&subjects(&["account:a"])).expect("free");
	let waiter = {
		let locks = locks.clone();
		std::thread::spawn(move || locks.hold(&subjects(&["account:a"])).is_ok())
	};
	while locks.stripes[0].waiting.load(Ordering::SeqCst) == 0 {
		std::thread::yield_now();
	}
	assert!(
		locks.hold(&subjects(&["account:a"])).is_err(),
		"one is waiting, the line holds one"
	);
	drop(first);
	assert!(
		waiter.join().expect("thread"),
		"the waiter is admitted in turn"
	);
}
