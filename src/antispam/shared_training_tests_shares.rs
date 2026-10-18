//! How the global budget of the shared corpus is shared among networks, and
//! the invariants of the whole budget under random sequences of jobs.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use super::tests::{v4, v6};
use super::*;

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
			let from = in_network(net, host);
			if budget.admit(now, &from, true).is_ok() {
				budget.release(&from, true);
			}
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
		let from = in_network(100, host);
		if budget.admit(now, &from, true).is_ok() {
			fresh += 1;
			budget.release(&from, true);
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
		for step in 0..30_000 {
			// The network under test speaks only once the others have spent
			// what they can, which is when a first come, first served budget
			// would have nothing left for it.
			if step >= 15_000 && rng.next(8) == 0 {
				let spam = rng.next(2) == 0;
				if victim_used[usize::from(spam)] < FIRST_JOBS {
					let from = in_network(200, rng.next(256) as u8);
					assert_eq!(
						budget.admit(now, &from, spam),
						Ok(()),
						"the network was held back after {} jobs",
						victim_used[usize::from(spam)]
					);
					budget.release(&from, spam);
					victim_used[usize::from(spam)] += 1;
				}
			} else {
				// The attackers: fifteen networks, any host, any kind.
				let from = in_network(rng.next(15) as u8, rng.next(256) as u8);
				let spam = rng.next(2) == 0;
				if budget.admit(now, &from, spam).is_ok() {
					budget.release(&from, spam);
				}
			}
		}
	}
}

/// A job the queue cannot take spends nothing of the budget: a full queue
/// is the server's state, not something the source did.
#[test]
fn a_job_a_full_queue_turns_away_spends_none_of_the_budget() {
	let (queue, mut receiver, budget) = SharedTraining::bounded(1);
	let now = Instant::now();
	let from = TrainSource::new(v4(1, 1), Some("verified.example"));
	let mut full = 0;
	for _ in 0..FINE_PER_WINDOW - 1 {
		if queue.try_submit(now, &from, "", b"x", false) == Err(Refusal::QueueFull) {
			full += 1;
		}
	}
	assert_eq!(
		full,
		FINE_PER_WINDOW - 2,
		"one job fits, the rest are turned away"
	);
	// The queue drains, and the source still has the rest of its hour.
	let mut taken = 0;
	while let Ok(job) = receiver.try_recv() {
		budget.release(&job.source, job.spam);
		taken += 1;
	}
	assert_eq!(taken, 1);
	for n in 0..FINE_PER_WINDOW - 1 {
		assert_eq!(
			queue.try_submit(now, &from, "", b"x", false),
			Ok(()),
			"submission {n} after the queue drained was refused"
		);
		let job = receiver.try_recv().expect("the job is queued");
		budget.release(&job.source, job.spam);
	}
}

/// Spread over many /24s, one network still cannot fill the queue that the
/// other networks share: 16 of its jobs may wait, not 64.
#[test]
fn one_network_cannot_fill_the_queue_by_spreading_over_its_blocks() {
	let (queue, _receiver, _budget) = SharedTraining::bounded(QUEUE_CAPACITY);
	let now = Instant::now();
	let mut accepted = 0;
	for host in 0..=u8::MAX {
		if queue
			.try_submit(now, &in_network(1, host), "", b"x", true)
			.is_ok()
		{
			accepted += 1;
		}
	}
	// Written out on purpose: a quarter of the queue.
	assert_eq!(accepted, 16);
	assert_eq!(
		queue.try_submit(now, &in_network(2, 1), "", b"x", true),
		Ok(())
	);
}
