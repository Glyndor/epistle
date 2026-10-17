//! The budget and the queue in front of the shared corpus.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use super::*;

fn v4(c: u8, d: u8) -> Option<IpAddr> {
	Some(IpAddr::V4(Ipv4Addr::new(192, 0, c, d)))
}

fn v6(text: &str) -> Option<IpAddr> {
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
		let forged = TrainSource::new(v4(n, 9), None);
		let _ = budget.admit(now, &forged, true);
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
fn a_source_without_keys_is_never_refused_by_the_per_key_budget() {
	let budget = Budget::default();
	let now = Instant::now();
	for _ in 0..1000 {
		assert_eq!(
			budget.admit(now, &TrainSource::unattributed(), false),
			Ok(())
		);
	}
	assert_eq!(budget.tracked(), (0, 0, 0));
}

#[test]
fn a_full_table_forgets_the_oldest_key_and_refuses_nobody() {
	let budget = Budget::with_table_size(4);
	let now = Instant::now();
	for n in 0..4 {
		let from = TrainSource::new(None, Some(&format!("d{n}.example")));
		budget.admit(now, &from, false).expect("room");
	}
	let newcomer = TrainSource::new(None, Some("new.example"));
	assert_eq!(budget.admit(now, &newcomer, false), Ok(()));
	assert_eq!(budget.tracked().1, 4);
	// d0 was the oldest and is forgotten: it starts from nothing, with no
	// share waiting. d3 still holds its job.
	let d0 = TrainSource::new(None, Some("d0.example"));
	let d3 = TrainSource::new(None, Some("d3.example"));
	assert_eq!(budget.pending(&d3, false), 1);
	assert_eq!(budget.admit(now, &d0, false), Ok(()));
	assert_eq!(budget.tracked().1, 4);
}

#[test]
fn using_a_key_keeps_it_from_being_the_oldest() {
	let budget = Budget::with_table_size(2);
	let now = Instant::now();
	let a = TrainSource::new(None, Some("a.example"));
	let b = TrainSource::new(None, Some("b.example"));
	let c = TrainSource::new(None, Some("c.example"));
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
	let domain = TrainSource::new(None, Some("kept.example"));
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
	assert!(queue.submit(&alone(1), "scope", &huge, true));
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

/// An address of network `net` (an IPv4 /16): `host` picks the /24 inside it,
/// so no finer key is shared between two hosts.
fn in_network(net: u8, host: u8) -> TrainSource {
	TrainSource::new(Some(IpAddr::V4(Ipv4Addr::new(20, net, host, 1))), None)
}

#[test]
fn a_whole_network_cannot_take_more_than_its_share_of_the_server() {
	let budget = Budget::default();
	let now = Instant::now();
	let mut accepted = 0;
	for host in 0..=u8::MAX {
		let from = in_network(1, host);
		if budget.admit(now, &from, true).is_ok() {
			accepted += 1;
			budget.release(&from, true);
		}
	}
	assert_eq!(accepted, BLOCK_PER_WINDOW);
	// The rest of the server is untouched by it.
	assert_eq!(budget.admit(now, &in_network(2, 1), true), Ok(()));
	assert_eq!(
		budget.admit(now, &in_network(1, 1), false),
		Ok(()),
		"ham is apart"
	);
}

#[test]
fn an_ipv6_network_is_a_slash_32() {
	let a = TrainSource::new(v6("2001:db8:1::1"), None);
	let b = TrainSource::new(v6("2001:db8:ffff:1::1"), None);
	let c = TrainSource::new(v6("2001:db9::1"), None);
	assert_eq!(
		a.addresses.as_ref().unwrap().2,
		b.addresses.as_ref().unwrap().2
	);
	assert_ne!(
		a.addresses.as_ref().unwrap().2,
		c.addresses.as_ref().unwrap().2
	);
}

#[test]
fn the_last_quarter_is_kept_for_networks_under_their_share() {
	let budget = Budget::default();
	let now = Instant::now();
	// Twelve networks spend the soft limit between them (12 * 125 = 1500).
	for net in 0..12 {
		for host in 0..=u8::MAX {
			let _ = budget.admit(now, &in_network(net, host), true);
		}
	}
	// A network that already used more than its first jobs is held back...
	let heavy = in_network(0, 200);
	assert_eq!(budget.admit(now, &heavy, true), Err(Refusal::OverBudget));
	// ...a network without a known address too...
	assert_eq!(
		budget.admit(now, &TrainSource::unattributed(), true),
		Err(Refusal::OverBudget)
	);
	// ...while a network under its fair share still trains, up to its first jobs.
	let mut fresh = 0;
	for host in 0..=u8::MAX {
		if budget.admit(now, &in_network(100, host), true).is_ok() {
			fresh += 1;
		}
	}
	assert_eq!(fresh, FIRST_JOBS);
}

#[test]
fn a_network_of_a_whole_slash_16_does_not_stop_another_network_from_training() {
	let budget = Budget::default();
	let now = Instant::now();
	for host in 0..=u8::MAX {
		for last in 0..=u8::MAX {
			let ip = Ipv4Addr::new(30, 7, host, last);
			let _ = budget.admit(now, &TrainSource::new(Some(IpAddr::V4(ip)), None), true);
		}
	}
	let honest = TrainSource::new(v4(1, 1), Some("friend.example"));
	assert_eq!(budget.admit(now, &honest, true), Ok(()));
	assert_eq!(budget.admit(now, &honest, false), Ok(()));
}

/// A deterministic stream of numbers for the property tests.
struct Rng(u64);

impl Rng {
	fn next(&mut self, below: u64) -> u64 {
		self.0 ^= self.0 << 13;
		self.0 ^= self.0 >> 7;
		self.0 ^= self.0 << 17;
		self.0 % below
	}
}

fn random_source(rng: &mut Rng, networks: u64) -> TrainSource {
	let net = rng.next(networks) as u8;
	let host = rng.next(256) as u8;
	let ip = if rng.next(3) == 0 {
		IpAddr::V6(Ipv6Addr::new(
			0x2001,
			0xdb8 + net as u16,
			rng.next(4) as u16,
			host as u16,
			0,
			0,
			0,
			1,
		))
	} else {
		IpAddr::V4(Ipv4Addr::new(40, net, host, rng.next(4) as u8 + 1))
	};
	let domain = match rng.next(4) {
		0 => Some(format!("d{}.example", rng.next(50))),
		_ => None,
	};
	TrainSource::new(Some(ip), domain.as_deref())
}

/// The state of a budget, for comparing before and after a refusal.
fn fingerprint(budget: &Budget) -> String {
	format!("{:?}", *budget.inner.lock().unwrap())
}

/// Random sequences of jobs from many sources, networks, kinds and moments,
/// checking after every step what the module documents as invariants 2 to 4,
/// on a table small enough to be evicted from and on one that is not.
#[test]
fn the_invariants_hold_under_random_sequences() {
	for (seed, table, networks, steps) in [
		(1u64, 64usize, 200u64, 30_000),
		(7, TABLE_SIZE, 120, 1_500),
		(99, 16, 255, 30_000),
		(5, 512, 4, 3_000),
		(11, 4096, 100, 1_500),
	] {
		let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
		let budget = Budget::with_table_size(table);
		let start = Instant::now();
		let mut now = start;
		let mut live: Vec<(TrainSource, bool)> = Vec::new();
		let mut global = [0u32; 2];
		let mut refused = 0u32;
		let mut peak = 0u32;
		let mut per_network: std::collections::HashMap<(u8, bool, u32), u32> = Default::default();
		for _ in 0..steps {
			if rng.next(500) == 0 {
				now += Duration::from_secs(rng.next(2 * WINDOW.as_secs()));
				global = [0; 2];
				per_network.clear();
			}
			// A job finishes now and then.
			if !live.is_empty() && rng.next(3) == 0 {
				let (source, spam) = live.swap_remove(rng.next(live.len() as u64) as usize);
				budget.release(&source, spam);
			}
			let source = random_source(&mut rng, networks);
			let spam = rng.next(2) == 0;
			let before = fingerprint(&budget);
			match budget.admit(now, &source, spam) {
				Ok(()) => {
					live.push((source.clone(), spam));
					global[usize::from(spam)] += 1;
					let (_, _, network) = source.addresses.clone().unwrap();
					*per_network
						.entry((network.len() as u8, spam, hash(&network)))
						.or_default() += 1;
				}
				Err(_) => {
					refused += 1;
					assert_eq!(before, fingerprint(&budget), "a refusal changed the state");
				}
			}
			assert!(global[0] <= GLOBAL_PER_WINDOW && global[1] <= GLOBAL_PER_WINDOW);
			if table >= networks as usize * 2 {
				assert!(per_network.values().all(|&used| used <= BLOCK_PER_WINDOW));
				peak = peak.max(per_network.values().copied().max().unwrap_or(0));
			}
			let (addresses, domains, nets) = budget.tracked();
			assert!(addresses <= table && domains <= table && nets <= table);
		}
		assert!(refused > 0, "seed {seed} never refused anything");
		if networks == 4 {
			assert!(
				peak > FIRST_JOBS,
				"no network ever used more than its first jobs"
			);
		}
	}
}

fn hash(text: &str) -> u32 {
	text.bytes()
		.fold(17u32, |h, b| h.wrapping_mul(31).wrapping_add(u32::from(b)))
}

/// Invariant 1 as a property: whatever up to fifteen other networks send,
/// of either kind and in any order, a network that sends at most its first
/// jobs of each kind is always admitted.
#[test]
fn a_network_under_its_first_jobs_always_trains_whatever_others_send() {
	for seed in 1..=20u64 {
		let mut rng = Rng(seed.wrapping_mul(0x2545_F491_4F6C_DD1D));
		let budget = Budget::default();
		let now = Instant::now();
		let mut victim_used = [0u32; 2];
		for _ in 0..6000 {
			if rng.next(8) == 0 {
				let spam = rng.next(2) == 0;
				if victim_used[usize::from(spam)] < FIRST_JOBS {
					let from = in_network(200, rng.next(256) as u8);
					assert_eq!(
						budget.admit(now, &from, spam),
						Ok(()),
						"the network was held back after {} jobs",
						victim_used[usize::from(spam)]
					);
					victim_used[usize::from(spam)] += 1;
				}
			} else {
				// The attackers: fifteen networks, any host, any kind.
				let from = in_network(rng.next(15) as u8, rng.next(256) as u8);
				let spam = rng.next(2) == 0;
				if budget.admit(now, &from, spam).is_ok() && rng.next(2) == 0 {
					budget.release(&from, spam);
				}
			}
		}
	}
}
