//! The budget and the queue in front of the shared corpus.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use super::*;

fn ip(last: u8) -> Option<IpAddr> {
	Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)))
}

fn source(last: u8) -> TrainSource {
	TrainSource::new(ip(last), None)
}

#[test]
fn an_address_in_the_same_v6_block_is_the_same_source() {
	let a = Some(IpAddr::V6(
		"2001:db8:1:2:aaaa::1".parse::<Ipv6Addr>().unwrap(),
	));
	let b = Some(IpAddr::V6(
		"2001:db8:1:2:bbbb::9".parse::<Ipv6Addr>().unwrap(),
	));
	let c = Some(IpAddr::V6("2001:db8:1:3::1".parse::<Ipv6Addr>().unwrap()));
	assert_eq!(TrainSource::new(a, None), TrainSource::new(b, None));
	assert_ne!(TrainSource::new(a, None), TrainSource::new(c, None));
}

#[test]
fn the_sender_domain_is_a_second_key_folded_to_lowercase_and_cut() {
	let plain = TrainSource::new(ip(1), Some("Example.NET"));
	assert_eq!(plain, TrainSource::new(ip(1), Some("example.net")));
	assert_ne!(plain, TrainSource::new(ip(1), None));
	assert_eq!(
		TrainSource::new(None, Some("")),
		TrainSource::unattributed()
	);
	let long = "é".repeat(MAX_DOMAIN_LEN);
	let cut = TrainSource::new(None, Some(&long));
	assert!(cut.keys[0].len() <= MAX_DOMAIN_LEN + "domain:".len());
}

#[test]
fn a_source_gets_a_budget_per_window_and_a_new_one_after_it() {
	let budget = Budget::default();
	let start = Instant::now();
	let s = source(1);
	for _ in 0..MAX_PER_WINDOW {
		budget.admit(start, &s).expect("within the budget");
		budget.release(&s);
	}
	assert_eq!(budget.admit(start, &s), Err(Refusal::OverBudget));
	let later = start + WINDOW;
	assert_eq!(budget.admit(later, &s), Ok(()));
}

#[test]
fn a_source_cannot_have_more_than_its_share_waiting() {
	let budget = Budget::default();
	let now = Instant::now();
	let s = source(1);
	for _ in 0..MAX_PENDING_PER_SOURCE {
		budget.admit(now, &s).expect("within the share");
	}
	assert_eq!(budget.admit(now, &s), Err(Refusal::TooManyPending));
	assert_eq!(budget.admit(now, &source(2)), Ok(()));
	budget.release(&s);
	assert_eq!(budget.admit(now, &s), Ok(()));
}

#[test]
fn nothing_is_counted_unless_every_key_has_room() {
	let budget = Budget::default();
	let now = Instant::now();
	let domain = Some("spam.example");
	for last in 0..MAX_PER_WINDOW as u8 {
		let from = TrainSource::new(ip(last), domain);
		budget.admit(now, &from).expect("within the budget");
		budget.release(&from);
	}
	// The domain is used up; a new address must not be charged for the refused job.
	let fresh = TrainSource::new(ip(200), domain);
	assert_eq!(budget.admit(now, &fresh), Err(Refusal::OverBudget));
	let only_ip = TrainSource::new(ip(200), None);
	for _ in 0..MAX_PENDING_PER_SOURCE {
		budget
			.admit(now, &only_ip)
			.expect("the address was not charged");
	}
}

#[test]
fn a_source_without_keys_is_never_refused_by_the_budget() {
	let budget = Budget::default();
	let now = Instant::now();
	for _ in 0..1000 {
		assert_eq!(budget.admit(now, &TrainSource::unattributed()), Ok(()));
	}
	assert_eq!(budget.tracked(), 0);
}

#[test]
fn the_table_of_sources_is_bounded_and_forgets_the_expired() {
	let budget = Budget::default();
	let start = Instant::now();
	for n in 0..MAX_SOURCES {
		let from = TrainSource::new(None, Some(&format!("d{n}.example")));
		budget.admit(start, &from).expect("room in the table");
	}
	assert_eq!(budget.tracked(), MAX_SOURCES);
	let newcomer = TrainSource::new(None, Some("new.example"));
	// Every entry still has a job waiting: nothing can be forgotten.
	assert_eq!(budget.admit(start, &newcomer), Err(Refusal::TableFull));
	assert_eq!(budget.tracked(), MAX_SOURCES);
	// Once the jobs are done and the window is over, the table makes room.
	for n in 0..MAX_SOURCES {
		budget.release(&TrainSource::new(None, Some(&format!("d{n}.example"))));
	}
	assert_eq!(budget.admit(start + WINDOW, &newcomer), Ok(()));
	assert_eq!(budget.tracked(), 1);
}

#[test]
fn a_full_queue_drops_the_job_and_gives_the_share_back() {
	let (queue, _receiver, budget) = SharedTraining::bounded(2);
	let now = Instant::now();
	let data = b"some text";
	assert_eq!(queue.try_submit(now, &source(1), "", data, true), Ok(()));
	assert_eq!(queue.try_submit(now, &source(2), "", data, true), Ok(()));
	assert_eq!(
		queue.try_submit(now, &source(3), "", data, true),
		Err(Refusal::QueueFull)
	);
	// The refused job holds no share: the same source fits once there is room.
	assert_eq!(budget.admit(now, &source(3)), Ok(()));
}

#[test]
fn one_source_cannot_fill_the_queue_for_the_rest() {
	let (queue, _receiver, _budget) = SharedTraining::bounded(QUEUE_CAPACITY);
	let now = Instant::now();
	let accepted = (0..200)
		.filter(|_| queue.try_submit(now, &source(1), "", b"x", true).is_ok())
		.count();
	assert_eq!(accepted, MAX_PENDING_PER_SOURCE as usize);
	assert_eq!(queue.try_submit(now, &source(2), "", b"x", false), Ok(()));
}

#[test]
fn without_a_source_only_the_queue_bounds_the_job() {
	let (queue, _receiver, _budget) = SharedTraining::bounded(10);
	let now = Instant::now();
	let accepted = (0..50)
		.filter(|_| {
			queue
				.try_submit(now, &TrainSource::unattributed(), "", b"x", true)
				.is_ok()
		})
		.count();
	assert_eq!(accepted, 10);
}

#[tokio::test]
async fn a_job_keeps_only_the_window_of_a_huge_message() {
	let (queue, mut receiver, _budget) = SharedTraining::bounded(4);
	let huge = vec![b'a'; 3 * MAX_TRAINING_BYTES];
	assert!(queue.submit(&source(1), "scope", &huge, true));
	let job = receiver.recv().await.expect("queued job");
	assert_eq!(job.text.len(), MAX_TRAINING_BYTES);
	assert_eq!(job.scope, "scope");
	assert!(job.spam);
}

#[tokio::test]
async fn submitting_never_waits_even_with_nobody_draining() {
	let (queue, _receiver, _budget) = SharedTraining::bounded(1);
	// A current-thread runtime with no other task: a `submit` that waited
	// for room would hang this test.
	for last in 0..50 {
		let _ = queue.submit(&source(last), "", b"x", true);
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
	let s = source(9);
	for _ in 0..MAX_PENDING_PER_SOURCE {
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
