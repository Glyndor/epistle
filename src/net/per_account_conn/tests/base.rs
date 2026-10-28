use super::*;

fn ip(s: &str) -> IpAddr {
	s.parse().unwrap()
}

#[test]
fn per_ip_cap_refuses_one_account_over_the_pair_limit() {
	let counter = Arc::new(PerAccountCounter::new(2, 50));
	let a = counter
		.try_acquire("alice", ip("203.0.113.1"))
		.expect("first");
	let b = counter
		.try_acquire("alice", ip("203.0.113.1"))
		.expect("second");
	assert_eq!(
		counter.try_acquire("alice", ip("203.0.113.1")).unwrap_err(),
		PerAccountRefusal::PerAccountPerIp,
		"the third connection from the same IP for the same account is refused"
	);
	drop(a);
	let c = counter
		.try_acquire("alice", ip("203.0.113.1"))
		.expect("third after drop");
	assert_eq!(counter.pair("alice", ip("203.0.113.1")), 2);
	drop(b);
	drop(c);
	assert_eq!(counter.total("alice"), 0);
	assert_eq!(counter.pair("alice", ip("203.0.113.1")), 0);
}

#[test]
fn the_total_cap_refuses_one_account_across_distinct_ip_addresses() {
	let counter = Arc::new(PerAccountCounter::new(50, 2));
	let a = counter
		.try_acquire("alice", ip("203.0.113.1"))
		.expect("first");
	let b = counter
		.try_acquire("alice", ip("203.0.113.2"))
		.expect("second");
	assert_eq!(
		counter.try_acquire("alice", ip("203.0.113.3")).unwrap_err(),
		PerAccountRefusal::PerAccountTotal,
		"the third IP is refused by the per-account total"
	);
	drop(a);
	let _c = counter
		.try_acquire("alice", ip("203.0.113.3"))
		.expect("third after drop");
	drop(b);
	assert_eq!(counter.total("alice"), 1);
}

#[test]
fn two_accounts_have_independent_counts() {
	let counter = Arc::new(PerAccountCounter::new(2, 2));
	let _a = counter
		.try_acquire("alice", ip("203.0.113.1"))
		.expect("alice");
	let _b = counter
		.try_acquire("alice", ip("203.0.113.2"))
		.expect("alice second");
	let _c = counter
		.try_acquire("bob", ip("203.0.113.1"))
		.expect("bob first");
	let _d = counter
		.try_acquire("bob", ip("203.0.113.2"))
		.expect("bob second");
	assert_eq!(
		counter.try_acquire("alice", ip("203.0.113.3")).unwrap_err(),
		PerAccountRefusal::PerAccountTotal,
		"alice's total of 2 is full"
	);
	assert_eq!(
		counter.try_acquire("bob", ip("203.0.113.3")).unwrap_err(),
		PerAccountRefusal::PerAccountTotal,
		"bob's total of 2 is full"
	);
}

#[test]
fn churn_through_a_thousand_distinct_pairs_leaves_an_empty_map() {
	// The counter's two maps are bounded by the number of distinct
	// pairs that hold a connection at the same time. A long stream
	// of distinct connections that all disconnect must not leave
	// any stale key behind: `Drop` removes the entry the moment its
	// count returns to zero, otherwise the maps grow without bound
	// under sustained churn.
	let counter = Arc::new(PerAccountCounter::new(10, 10_000));
	for index in 0..1_000_u32 {
		let account = format!("user{index}");
		let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(
			203,
			0,
			113,
			((index >> 8) & 0xff) as u8,
		));
		let slot = counter.try_acquire(&account, ip).expect("acquire");
		assert_eq!(counter.pair(&account, ip), 1);
		drop(slot);
		assert_eq!(counter.pair(&account, ip), 0);
		assert_eq!(counter.total(&account), 0);
	}
	assert_eq!(
		counter.tracked_pairs(),
		0,
		"no (account, IP) pair may outlive its slot"
	);
	assert_eq!(
		counter.tracked_accounts(),
		0,
		"no account may outlive its slot"
	);
}
