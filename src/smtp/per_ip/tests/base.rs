
use super::*;

#[test]
fn cap_refuses_extra_connections_from_same_ip() {
	let counter = Arc::new(PerIpCounter::new(2));
	let peer: IpAddr = "203.0.113.1".parse().unwrap();
	let a = counter.try_acquire(peer, &[]).expect("first");
	let b = counter.try_acquire(peer, &[]).expect("second");
	assert!(counter.try_acquire(peer, &[]).is_none(), "third refused");
	drop(a);
	assert!(
		counter.try_acquire(peer, &[]).is_some(),
		"slot freed by drop"
	);
	drop(b);
	assert_eq!(counter.count(peer), 0);
}

#[test]
fn different_ips_track_independently() {
	let counter = Arc::new(PerIpCounter::new(1));
	let a: IpAddr = "203.0.113.1".parse().unwrap();
	let b: IpAddr = "203.0.113.2".parse().unwrap();
	let slot_a = counter.try_acquire(a, &[]).expect("a first");
	assert!(
		counter.try_acquire(b, &[]).is_some(),
		"b has its own counter, independent of a"
	);
	assert!(
		counter.try_acquire(a, &[]).is_none(),
		"a is over the cap of 1"
	);
	drop(slot_a);
	assert!(counter.try_acquire(a, &[]).is_some());
}

#[test]
fn ipv6_addresses_in_one_slash_64_share_the_cap() {
	// One subscriber is handed a whole /64; rotating through it must
	// not buy another connection.
	let counter = Arc::new(PerIpCounter::new(2));
	let first: IpAddr = "2001:db8:1:2::1".parse().unwrap();
	let second: IpAddr = "2001:db8:1:2::2".parse().unwrap();
	let third: IpAddr = "2001:db8:1:2:ffff:ffff:ffff:ffff".parse().unwrap();
	let other: IpAddr = "2001:db8:1:3::1".parse().unwrap();
	let _a = counter.try_acquire(first, &[]).expect("first");
	let _b = counter.try_acquire(second, &[]).expect("second");
	assert!(
		counter.try_acquire(third, &[]).is_none(),
		"a third address in the same /64 is over the cap"
	);
	assert!(
		counter.try_acquire(other, &[]).is_some(),
		"the next /64 is another client"
	);
}

#[test]
fn an_ipv4_mapped_peer_counts_as_its_ipv4_address() {
	let counter = Arc::new(PerIpCounter::new(1));
	let plain: IpAddr = "203.0.113.1".parse().unwrap();
	let mapped: IpAddr = "::ffff:203.0.113.1".parse().unwrap();
	let _slot = counter.try_acquire(plain, &[]).expect("plain");
	assert!(
		counter.try_acquire(mapped, &[]).is_none(),
		"the mapped form is the same client"
	);
}

#[test]
fn the_map_forgets_a_client_whose_connections_have_all_ended() {
	// The key is chosen by whoever connects, so a leftover entry per
	// address would let a client grow the map without bound.
	let counter = Arc::new(PerIpCounter::new(2));
	for n in 0..1000u32 {
		let v4: IpAddr = std::net::Ipv4Addr::from(0x0a00_0000 + n).into();
		let v6: IpAddr = std::net::Ipv6Addr::from((u128::from(n) + 1) << 64).into();
		let first = counter.try_acquire(v4, &[]).expect("v4");
		let second = counter.try_acquire(v6, &[]).expect("v6");
		assert_eq!(counter.tracked(), 2);
		drop((first, second));
		assert_eq!(counter.tracked(), 0, "entry {n} was left behind");
	}
}

#[test]
fn trusted_cidrs_bypass_the_cap() {
	let counter = Arc::new(PerIpCounter::new(1));
	let peer: IpAddr = "10.0.0.5".parse().unwrap();
	let trusted = vec![crate::cidr::Cidr::parse("10.0.0.0/8").unwrap()];
	assert!(counter.try_acquire(peer, &trusted).is_some());
	// Second slot is admitted even though the cap is 1.
	assert!(counter.try_acquire(peer, &trusted).is_some());
}
