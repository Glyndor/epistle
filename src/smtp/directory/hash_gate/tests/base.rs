//! The gate keeps password checks to a few at a time and turns away the ones
//! that find the line full. These count checks running, not time.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, mpsc};
use std::time::{Duration, Instant};

use super::*;
use crate::antispam::bans::BanPolicy;
use crate::antispam::bans::tests::base::FakeBanStore;
use crate::config::Protocol;
use crate::smtp::directory::Directory;
use crate::smtp::directory::gate_fixture::*;
use crate::smtp::directory::tests::bans::decoy_counters::DecoyCounters;
use crate::test_fixtures as fixtures;

/// A gate whose only place is taken, and what holds it. Dropping the holder
/// gives the place back. The holder gives up after a while on its own, so a
/// test that forgets it cannot leave the suite waiting.
pub(crate) struct Occupied {
	release: Option<mpsc::Sender<()>>,
	thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Occupied {
	fn drop(&mut self) {
		drop(self.release.take());
		if let Some(thread) = self.thread.take() {
			let _ = thread.join();
		}
	}
}

/// A gate of one place and no line, with the place taken.
pub(crate) fn full_gate() -> (Arc<HashGate>, Occupied) {
	let gate = Arc::new(HashGate::new(1, 0));
	let (release, hold) = mpsc::channel::<()>();
	let thread = {
		let gate = gate.clone();
		std::thread::spawn(move || {
			let _ = gate.run(|| hold.recv_timeout(Duration::from_secs(5)));
		})
	};
	wait_until("the holder to take the place", || gate.load().0 == 1);
	(
		gate,
		Occupied {
			release: Some(release),
			thread: Some(thread),
		},
	)
}

/// Wait until `ready` holds, or fail the test: a poll on a condition with a
/// deadline, never a sleep standing in for synchronisation.
pub(crate) fn wait_until(what: &str, ready: impl Fn() -> bool) {
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
	wait_until("every caller to finish", || {
		threads.iter().all(|thread| thread.is_finished())
	});
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
		std::thread::spawn(move || gate.run(|| hold.recv_timeout(Duration::from_secs(5))))
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
	wait_until("the holder to finish", || holder.is_finished());
	wait_until("the waiter to get the place", || waiter.is_finished());
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
	let gate = Arc::new(gate);
	let again = {
		let gate = gate.clone();
		std::thread::spawn(move || gate.run(|| 7))
	};
	wait_until("the place to be free again", || again.is_finished());
	assert_eq!(again.join().expect("thread"), Ok(7));
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
	let (gate, occupied) = full_gate();
	let metrics = Arc::new(crate::metrics::Metrics::new());
	let (directory, store, counters) = directory_with(&gate);
	let directory = directory.with_metrics(metrics.clone());
	let ip = Some("203.0.113.5".parse().expect("address"));
	for login in [OPEN, "nobody-here", DISABLED] {
		let verdict =
			directory.authenticate_verdict(login, fixtures::password(), ip, Protocol::Imaps);
		assert_eq!(verdict, Verdict::Busy, "{login} found the gate full");
		let plain =
			directory.authenticate_with_ip(login, fixtures::password(), ip, Protocol::Imaps);
		assert_eq!(
			plain, None,
			"{login}: callers that cannot tell see a refusal"
		);
	}
	assert_eq!(counters.hashes(), 0, "nothing was hashed");
	assert_eq!(
		store.call_count("record_failure"),
		0,
		"an account that was never tried takes no strike"
	);
	let rendered = metrics.render();
	assert!(
		rendered.contains("mail_auth_hash_gate_rejected_total 6\n"),
		"{rendered}"
	);
	assert!(
		rendered.contains("mail_auth_login_failed_total 0\n"),
		"a turned-away sign-in is not a failed login"
	);
	drop(occupied);
	let admitted = directory.authenticate_with_ip(OPEN, fixtures::password(), ip, Protocol::Imaps);
	assert_eq!(admitted.as_deref(), Some(OPEN), "a free place admits again");
	let refused =
		directory.authenticate_verdict(OPEN, fixtures::wrong_password(), ip, Protocol::Imaps);
	assert_eq!(
		refused,
		Verdict::Refused,
		"a wrong password is still a refusal"
	);
}

#[test]
fn the_sizes_of_production_follow_the_cores() {
	for (cores, expected) in [
		(0, (2, 32)),
		(1, (2, 32)),
		(4, (2, 32)),
		(8, (4, 64)),
		(16, (8, 128)),
		(64, (8, 128)),
	] {
		assert_eq!(HashGate::sizes_for(cores), expected, "{cores} cores");
	}
}

#[test]
fn every_directory_shares_one_gate() {
	let one = Directory::new([], []);
	let other = Directory::new([], []);
	assert!(Arc::ptr_eq(&one.hash_gate, &other.hash_gate));
}

#[test]
fn a_flood_of_turned_away_sign_ins_logs_once_in_a_while() {
	let gate = HashGate::new(1, 0);
	assert_eq!(gate.note_rejected(1000), Some(1), "the first is told");
	for second in 1001..1030 {
		assert_eq!(gate.note_rejected(second), None, "at {second}");
	}
	assert_eq!(
		gate.note_rejected(1030),
		Some(30),
		"the next, with the count"
	);
	assert_eq!(gate.note_rejected(1031), None);
}

/// The reason the check runs inside the gate at all: a check waiting for a
/// place gives its worker to other tasks. With one worker, the task that
/// would release the place can only run if the waiting one let go of it.
/// The wait is bounded so a regression fails and does not hang.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn a_check_waiting_in_the_gate_leaves_the_worker_to_other_tasks() {
	let gate = Arc::new(HashGate::new(1, 0));
	let (release, hold) = mpsc::channel::<()>();
	let inside = {
		let gate = gate.clone();
		tokio::spawn(async move { gate.run(|| hold.recv_timeout(Duration::from_secs(5))) })
	};
	let other = tokio::spawn(async move { release.send(()).is_ok() });
	let sent = other.await.expect("other");
	let ran = inside.await.expect("inside");
	assert!(sent);
	ran.expect("a free place")
		.expect("released before the wait ran out: the worker was kept inside the gate");
}
