//! The budget and the queue in front of the shared corpus.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use super::*;
use crate::antispam::training_queue::MAX_TRAINING_BYTES;

pub(super) fn v4(c: u8, d: u8) -> Option<IpAddr> {
	Some(IpAddr::V4(Ipv4Addr::new(192, 0, c, d)))
}

pub(super) fn v6(text: &str) -> Option<IpAddr> {
	Some(IpAddr::V6(text.parse::<Ipv6Addr>().expect("ipv6")))
}

/// A source that is one IPv4 address in its own /24.
fn alone(n: u8) -> TrainSource {
	TrainSource::new(Some(IpAddr::V4(Ipv4Addr::new(10, n, 0, 1))), None)
}

#[test]
fn an_address_is_counted_by_its_block_and_by_the_wider_one() {
	let same_64_a = TrainSource::new(v6("2001:db8:1:2:aaaa::1"), None);
	let same_64_b = TrainSource::new(v6("2001:db8:1:2:bbbb::9"), None);
	let same_48 = TrainSource::new(v6("2001:db8:1:3::1"), None);
	let other_48 = TrainSource::new(v6("2001:db8:2:2::1"), None);
	assert_eq!(same_64_a, same_64_b);
	assert_ne!(same_64_a, same_48);
	// Different /64, same /48: the wider key is shared.
	assert_eq!(
		same_64_a.addresses.as_ref().unwrap().1,
		same_48.addresses.as_ref().unwrap().1
	);
	assert_ne!(
		same_64_a.addresses.as_ref().unwrap().1,
		other_48.addresses.as_ref().unwrap().1
	);
	let a = TrainSource::new(v4(1, 5), None);
	let b = TrainSource::new(v4(1, 200), None);
	let c = TrainSource::new(v4(2, 5), None);
	assert_ne!(
		a.addresses.as_ref().unwrap().0,
		b.addresses.as_ref().unwrap().0
	);
	assert_eq!(
		a.addresses.as_ref().unwrap().1,
		b.addresses.as_ref().unwrap().1
	);
	assert_ne!(
		a.addresses.as_ref().unwrap().1,
		c.addresses.as_ref().unwrap().1
	);
}

#[test]
fn a_domain_is_folded_to_lowercase_and_cut() {
	let plain = TrainSource::new(None, Some("Example.NET"));
	assert_eq!(plain, TrainSource::new(None, Some("example.net")));
	assert_ne!(plain, TrainSource::unattributed());
	assert_eq!(
		TrainSource::new(None, Some("")),
		TrainSource::unattributed()
	);
	let long = "é".repeat(MAX_DOMAIN_LEN);
	let cut = TrainSource::new(None, Some(&long));
	assert!(cut.domain.as_ref().unwrap().len() <= MAX_DOMAIN_LEN);
}

#[test]
fn a_key_gets_a_budget_per_window_and_a_new_one_after_it() {
	let budget = Budget::default();
	let start = Instant::now();
	let s = alone(1);
	for _ in 0..FINE_PER_WINDOW {
		budget.admit(start, &s, true).expect("within the budget");
		budget.release(&s, true);
	}
	assert_eq!(budget.admit(start, &s, true), Err(Refusal::OverBudget));
	assert_eq!(budget.admit(start + WINDOW, &s, true), Ok(()));
}

#[test]
fn ham_and_spam_have_budgets_apart() {
	let budget = Budget::default();
	let now = Instant::now();
	let s = TrainSource::new(v4(1, 1), Some("sender.example"));
	for _ in 0..FINE_PER_WINDOW {
		budget.admit(now, &s, true).expect("spam within the budget");
		budget.release(&s, true);
	}
	assert_eq!(budget.admit(now, &s, true), Err(Refusal::OverBudget));
	// The same address and domain still have all of their ham.
	for _ in 0..FINE_PER_WINDOW {
		budget.admit(now, &s, false).expect("ham is untouched");
		budget.release(&s, false);
	}
	assert_eq!(budget.admit(now, &s, false), Err(Refusal::OverBudget));
}

#[test]
fn a_key_cannot_have_more_than_its_share_waiting() {
	let budget = Budget::default();
	let now = Instant::now();
	let s = alone(1);
	for _ in 0..FINE_PENDING {
		budget.admit(now, &s, false).expect("within the share");
	}
	assert_eq!(budget.admit(now, &s, false), Err(Refusal::TooManyPending));
	assert_eq!(budget.admit(now, &alone(2), false), Ok(()));
	budget.release(&s, false);
	assert_eq!(budget.admit(now, &s, false), Ok(()));
}

#[test]
fn nothing_is_counted_unless_every_key_has_room() {
	let budget = Budget::default();
	let now = Instant::now();
	let domain = Some("verified.example");
	for n in 0..FINE_PER_WINDOW as u8 {
		let from = TrainSource::new(v4(n, 1), domain);
		budget.admit(now, &from, false).expect("within the budget");
		budget.release(&from, false);
	}
	// The domain is used up; a new address must not be charged for the refused job.
	let fresh = TrainSource::new(v4(200, 1), domain);
	assert_eq!(budget.admit(now, &fresh, false), Err(Refusal::OverBudget));
	let only_ip = TrainSource::new(v4(200, 1), None);
	for _ in 0..FINE_PENDING {
		budget
			.admit(now, &only_ip, false)
			.expect("the address was not charged");
	}
}

/// A client cannot spend the budget of a domain it does not own: without
/// the server's verification the domain is not a key at all.
#[test]
fn an_unverified_domain_is_no_key_and_spends_nothing_of_a_verified_one() {
	let budget = Budget::default();
	let now = Instant::now();
	let victim = "bank.example";
	// A forger on its own address names the victim's domain in every message
	// the server did not verify: the server builds those sources without it.
	for n in 0..200u8 {
		let _ = budget.admit(now, &alone(n), true);
	}
	assert_eq!(budget.tracked().1, 0, "no domain key from unverified mail");
	// The real sender, verified from its own address, has its whole budget.
	for _ in 0..FINE_PENDING {
		let real = TrainSource::new(v4(250, 1), Some(victim));
		budget
			.admit(now, &real, false)
			.expect("the real sender is untouched");
	}
}

#[test]
fn the_whole_server_has_a_budget_per_kind() {
	let budget = Budget::default();
	let now = Instant::now();
	let mut accepted = 0;
	for n in 0..=u8::MAX {
		for m in 0..16u8 {
			let from = TrainSource::new(Some(IpAddr::V4(Ipv4Addr::new(100, n, m, 1))), None);
			if budget.admit(now, &from, true).is_ok() {
				accepted += 1;
				budget.release(&from, true);
			}
		}
	}
	assert_eq!(accepted, GLOBAL_PER_WINDOW);
	// Ham is another budget.
	assert_eq!(budget.admit(now, &alone(1), false), Ok(()));
}

#[test]
fn a_source_without_keys_is_one_small_network_with_the_budget_of_one() {
	let budget = Budget::default();
	let now = Instant::now();
	let mut accepted = 0;
	for _ in 0..1000 {
		if budget
			.admit(now, &TrainSource::unattributed(), false)
			.is_ok()
		{
			accepted += 1;
			budget.release(&TrainSource::unattributed(), false);
		}
	}
	assert_eq!(accepted, BLOCK_PER_WINDOW);
	// No address and no domain key; only the network of its own.
	assert_eq!(budget.tracked(), (0, 0, 1));
}

/// A source with a verified domain and an address of its own network.
fn named(n: u8, domain: &str) -> TrainSource {
	TrainSource::new(Some(IpAddr::V4(Ipv4Addr::new(10, n, 0, 1))), Some(domain))
}

#[test]
fn a_full_table_forgets_the_oldest_key_and_refuses_nobody() {
	let budget = Budget::with_table_size(4);
	let now = Instant::now();
	for n in 0..4 {
		let from = named(n, &format!("d{n}.example"));
		budget.admit(now, &from, false).expect("room");
	}
	let newcomer = named(9, "new.example");
	assert_eq!(budget.admit(now, &newcomer, false), Ok(()));
	assert_eq!(budget.tracked().1, 4);
	// d0 was the oldest and is forgotten: it starts from nothing, with no
	// share waiting. d3 still holds its job.
	let d0 = named(0, "d0.example");
	let d3 = named(3, "d3.example");
	assert_eq!(budget.pending(&d3, false), 1);
	assert_eq!(budget.admit(now, &d0, false), Ok(()));
	assert_eq!(budget.tracked().1, 4);
}

#[test]
fn using_a_key_keeps_it_from_being_the_oldest() {
	let budget = Budget::with_table_size(2);
	let now = Instant::now();
	let a = named(1, "a.example");
	let b = named(2, "b.example");
	let c = named(3, "c.example");
	budget.admit(now, &a, false).expect("a");
	budget.admit(now, &b, false).expect("b");
	budget.admit(now, &a, false).expect("a again");
	budget.admit(now, &c, false).expect("c evicts b");
	assert_eq!(budget.pending(&a, false), 2);
	assert_eq!(budget.pending(&b, false), 0);
}

#[test]
fn rotating_addresses_cannot_push_a_domain_out_of_its_table() {
	let budget = Budget::with_table_size(8);
	let now = Instant::now();
	let domain = named(250, "kept.example");
	budget.admit(now, &domain, false).expect("domain");
	for n in 0..=u8::MAX {
		let _ = budget.admit(now, &TrainSource::new(v4(n, 1), None), true);
	}
	assert_eq!(budget.tracked().0, 8);
	assert_eq!(budget.tracked().1, 1);
	assert_eq!(budget.pending(&domain, false), 1);
}

/// One million IPv6 addresses of one /48 (65536 /64 blocks, sixteen
/// addresses each): the tables stay at their size, the /48 gets only its
/// own budget, and a source elsewhere trains as if nothing happened.
#[test]
fn a_million_addresses_of_one_block_cannot_fill_the_tables_or_lock_others_out() {
	let budget = Budget::default();
	let now = Instant::now();
	let mut accepted = 0u32;
	for n in 0..1_000_000u32 {
		let ip = Ipv6Addr::new(
			0x2001,
			0xdb8,
			0x48,
			(n >> 4) as u16,
			0,
			0,
			0,
			(n & 0xf) as u16 + 1,
		);
		let from = TrainSource::new(Some(IpAddr::V6(ip)), None);
		if budget.admit(now, &from, true).is_ok() {
			accepted += 1;
			budget.release(&from, true);
		}
	}
	let (addresses, domains, networks) = budget.tracked();
	assert!(
		addresses <= TABLE_SIZE && domains == 0 && networks == 1,
		"tables grew to {addresses}/{domains}/{networks}"
	);
	assert_eq!(
		accepted, COARSE_PER_WINDOW,
		"the /48 got more than its block budget"
	);
	// Someone else, from another /48, trains.
	let honest = TrainSource::new(v6("2001:db8:77:1::5"), Some("friend.example"));
	assert_eq!(budget.admit(now, &honest, true), Ok(()));
	assert_eq!(budget.admit(now, &honest, false), Ok(()));
}

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
	let mut huge = vec![b'a'; 3 * MAX_TRAINING_BYTES];
	huge[..5].copy_from_slice(b"start");
	let end = huge.len();
	huge[end - 3..].copy_from_slice(b"end");
	assert!(queue.submit(&alone(1), "scope", &huge, true));
	let job = receiver.recv().await.expect("queued job");
	assert_eq!(job.text.len(), MAX_TRAINING_BYTES);
	assert!(job.text.starts_with(b"start") && job.text.ends_with(b"end"));
	assert_eq!(job.scope, "scope");
	assert!(job.spam);
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
