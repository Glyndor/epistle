//! The gate keeps password checks to a few at a time and turns away the ones
//! that find the line full. These count checks running, not time.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, mpsc};
use std::time::{Duration, Instant};

use super::*;
use crate::antispam::bans::BanPolicy;
use crate::antispam::bans::tests::FakeBanStore;
use crate::config::Protocol;
use crate::smtp::directory::Directory;
use crate::smtp::directory::decoy_counters::DecoyCounters;
use crate::smtp::directory::gate_fixture::*;
use crate::test_fixtures as fixtures;

/// Wait until `ready` holds, or fail the test: a poll on a condition with a
/// deadline, never a sleep standing in for synchronisation.
fn wait_until(what: &str, ready: impl Fn() -> bool) {
	let deadline = Instant::now() + Duration::from_secs(10);
	while !ready() {
		assert!(Instant::now() < deadline, "gave up waiting for {what}");
		std::thread::yield_now();
	}
}

#[test]
fn no_more_checks_run_at_once_than_the_gate_has_places() {
	let gate = Arc::new(HashGate::new(2, usize::MAX));
	let inside = Arc::new(AtomicUsize::new(0));
	let most = Arc::new(AtomicUsize::new(0));
	let start = Arc::new(Barrier::new(8));
	let threads: Vec<_> = (0..8)
		.map(|_| {
			let (gate, inside, most, start) =
				(gate.clone(), inside.clone(), most.clone(), start.clone());
			std::thread::spawn(move || {
				start.wait();
				gate.run(|| {
					let now = inside.fetch_add(1, Ordering::SeqCst) + 1;
					most.fetch_max(now, Ordering::SeqCst);
					std::thread::sleep(Duration::from_millis(20));
					inside.fetch_sub(1, Ordering::SeqCst);
				})
				.expect("a line without a limit never turns anyone away");
			})
		})
		.collect();
	for thread in threads {
		thread.join().expect("thread");
	}
	assert_eq!(most.load(Ordering::SeqCst), 2, "two places, eight callers");
	assert_eq!(gate.peak(), 2);
	assert_eq!(gate.load(), (0, 0), "every place was given back");
}

#[test]
fn a_full_line_turns_the_attempt_away_without_running_it() {
	let gate = Arc::new(HashGate::new(1, 1));
	let (release, hold) = mpsc::channel::<()>();
	let holder = {
		let gate = gate.clone();
		std::thread::spawn(move || gate.run(|| hold.recv()))
	};
	wait_until("the holder to take the place", || gate.load().0 == 1);
	let waiter = {
		let gate = gate.clone();
		std::thread::spawn(move || gate.run(|| "ran"))
	};
	wait_until("the waiter to join the line", || gate.load().1 == 1);
	// On its own thread: a gate that did not turn it away would leave it
	// waiting, and the test must fail rather than hang.
	let ran = Arc::new(AtomicUsize::new(0));
	let turned_away = {
		let (gate, ran) = (gate.clone(), ran.clone());
		std::thread::spawn(move || gate.run(|| ran.fetch_add(1, Ordering::SeqCst)))
	};
	wait_until("the full line to answer", || turned_away.is_finished());
	assert_eq!(turned_away.join().expect("thread"), Err(Busy));
	assert_eq!(
		ran.load(Ordering::SeqCst),
		0,
		"a refused attempt did no work"
	);
	release.send(()).expect("release");
	holder
		.join()
		.expect("holder")
		.expect("the holder ran")
		.expect("released");
	assert_eq!(waiter.join().expect("waiter"), Ok("ran"));
	assert_eq!(gate.load(), (0, 0));
}

#[test]
fn a_check_that_panics_gives_its_place_back() {
	let gate = HashGate::new(1, 0);
	let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
		let _ = gate.run(|| panic!("hashing failed"));
	}));
	assert!(crashed.is_err());
	assert_eq!(gate.load(), (0, 0), "no place is left held");
	assert_eq!(gate.run(|| 7), Ok(7), "the place was free again");
}

/// A directory with one place and no line, a fake ban store, and the counters
/// of the work it does.
fn directory_with(gate: &Arc<HashGate>) -> (Directory, FakeBanStore, Arc<DecoyCounters>) {
	let store = FakeBanStore::new(BanPolicy::default());
	let counters = Arc::new(DecoyCounters::default());
	let directory = gate_directory()
		.with_ban_store(Arc::new(store.clone()))
		.with_decoy_counters(counters.clone())
		.with_hash_gate(gate.clone());
	(directory, store, counters)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_password_check_goes_through_the_gate() {
	let gate = Arc::new(HashGate::new(2, usize::MAX));
	let (directory, _, _) = directory_with(&gate);
	assert_eq!(gate.peak(), 0);
	let right = directory.authenticate(OPEN, fixtures::password(), Protocol::Imaps);
	assert_eq!(right.as_deref(), Some(OPEN));
	assert_eq!(gate.peak(), 1, "a right password");
	let before = gate.load();
	assert_eq!(
		directory.authenticate("nobody-here", fixtures::wrong_password(), Protocol::Imaps),
		None
	);
	assert_eq!(gate.load(), before, "and its place is given back");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_attempt_turned_away_hashes_nothing_and_moves_no_strike() {
	let gate = Arc::new(HashGate::new(1, 0));
	let (directory, store, counters) = directory_with(&gate);
	let (release, hold) = mpsc::channel::<()>();
	let holder = {
		let gate = gate.clone();
		std::thread::spawn(move || gate.run(|| hold.recv()))
	};
	wait_until("the holder to take the place", || gate.load().0 == 1);
	let ip = Some("203.0.113.5".parse().expect("address"));
	for login in [OPEN, "nobody-here"] {
		let refused =
			directory.authenticate_with_ip(login, fixtures::password(), ip, Protocol::Imaps);
		assert_eq!(refused, None, "{login} found the gate full");
	}
	assert_eq!(counters.hashes(), 0, "nothing was hashed");
	assert_eq!(
		store.call_count("record_failure"),
		0,
		"an account that was never tried takes no strike"
	);
	release.send(()).expect("release");
	holder
		.join()
		.expect("holder")
		.expect("the holder ran")
		.expect("released");
	let admitted = directory.authenticate_with_ip(OPEN, fixtures::password(), ip, Protocol::Imaps);
	assert_eq!(admitted.as_deref(), Some(OPEN), "a free place admits again");
}
