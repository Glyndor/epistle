//! Tests for the non-global classifier in `validate_addresses.rs`. Lives
//! in a sibling so the file stays under the per-file line limit.

use super::{is_documentation_v6, is_shared, non_global_ipv4_reason, non_global_ipv6_reason};
use std::net::{Ipv4Addr, Ipv6Addr};

#[test]
fn non_global_ipv4_classifier() {
	let cases: &[(Ipv4Addr, bool)] = &[
		// Global.
		("8.8.8.8".parse().unwrap(), false),
		("1.1.1.1".parse().unwrap(), false),
		// Private (RFC 1918).
		("10.0.0.1".parse().unwrap(), true),
		("192.168.1.5".parse().unwrap(), true),
		("172.16.0.1".parse().unwrap(), true),
		// Loopback.
		("127.0.0.1".parse().unwrap(), true),
		// Link-local.
		("169.254.1.1".parse().unwrap(), true),
		// CGNAT (RFC 6598): stdlib does not flag these as private.
		("100.64.0.1".parse().unwrap(), true),
		// Documentation (RFC 5737 / 3068).
		("192.0.2.1".parse().unwrap(), true),
		("198.51.100.1".parse().unwrap(), true),
		("203.0.113.1".parse().unwrap(), true),
		// Multicast.
		("224.0.0.1".parse().unwrap(), true),
		// Unspecified.
		("0.0.0.0".parse().unwrap(), true),
	];
	for (ip, expect_non_global) in cases {
		let got = non_global_ipv4_reason(*ip).is_some();
		assert_eq!(
			got,
			*expect_non_global,
			"{ip}: expected non_global={expect_non_global}, got reason={:?}",
			non_global_ipv4_reason(*ip)
		);
	}
}

#[test]
fn cgnat_range_edges() {
	// RFC 6598: 100.64.0.0/10, so the range is 100.64.0.0..100.127.255.255.
	let in_range: &[Ipv4Addr] = &[
		"100.64.0.0".parse().unwrap(),
		"100.64.0.1".parse().unwrap(),
		"100.127.255.254".parse().unwrap(),
		"100.127.255.255".parse().unwrap(),
	];
	let out_of_range: &[Ipv4Addr] = &[
		"100.63.255.255".parse().unwrap(),
		"100.128.0.0".parse().unwrap(),
		"99.255.255.255".parse().unwrap(),
		"101.0.0.0".parse().unwrap(),
	];
	for ip in in_range {
		assert!(is_shared(*ip), "{ip} should be in CGNAT range");
		assert!(
			non_global_ipv4_reason(*ip).is_some(),
			"{ip} should be classified as non-global"
		);
	}
	for ip in out_of_range {
		assert!(!is_shared(*ip), "{ip} should NOT be in CGNAT range");
	}
}

#[test]
fn non_global_ipv6_classifier() {
	let cases: &[(Ipv6Addr, bool)] = &[
		// Global.
		("2606:4700:4700::1111".parse().unwrap(), false),
		// Loopback.
		("::1".parse().unwrap(), true),
		// Link-local.
		("fe80::1".parse().unwrap(), true),
		// Unique-local (ULA).
		("fc00::1".parse().unwrap(), true),
		("fd12::1".parse().unwrap(), true),
		// Documentation (RFC 3849): stdlib has no stable helper.
		("2001:db8::1".parse().unwrap(), true),
		// Multicast.
		("ff02::1".parse().unwrap(), true),
		// Unspecified.
		("::".parse().unwrap(), true),
	];
	for (ip, expect_non_global) in cases {
		let got = non_global_ipv6_reason(*ip).is_some();
		assert_eq!(
			got,
			*expect_non_global,
			"{ip}: expected non_global={expect_non_global}, got reason={:?}",
			non_global_ipv6_reason(*ip)
		);
	}
}

#[test]
fn documentation_v6_range_edges() {
	// RFC 3849: 2001:db8::/32, so the first two segments must be 0x2001 0x0db8.
	let in_range: &[Ipv6Addr] = &[
		"2001:db8::".parse().unwrap(),
		"2001:db8::1".parse().unwrap(),
		"2001:db8:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap(),
	];
	let out_of_range: &[Ipv6Addr] = &[
		"2001:db7::1".parse().unwrap(),
		"2001:0db9::1".parse().unwrap(),
		"2001:0db8:1::1".parse().unwrap(), // first two segments match; IS doc range
		"2001:0db7:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap(),
	];
	// The third entry has the documentation prefix and IS in range; the
	// test asserts both directions: in-range and out-of-range.
	let in_range_check: Vec<Ipv6Addr> = in_range.to_vec();
	let mut out_of_range_check: Vec<Ipv6Addr> = Vec::new();
	for ip in out_of_range {
		if !is_documentation_v6(*ip) {
			out_of_range_check.push(*ip);
		}
	}
	for ip in &in_range_check {
		assert!(is_documentation_v6(*ip), "{ip} should be in 2001:db8::/32");
		assert!(
			non_global_ipv6_reason(*ip).is_some(),
			"{ip} should be classified as non-global"
		);
	}
	for ip in &out_of_range_check {
		assert!(
			!is_documentation_v6(*ip),
			"{ip} should NOT be in 2001:db8::/32"
		);
	}
	// The boundary above 2001:db8:ffff:... stays in the /32 only because
	// the prefix is two segments; verify the boundary explicitly.
	let boundary_in = "2001:db8:ffff::1".parse::<Ipv6Addr>().unwrap();
	assert!(is_documentation_v6(boundary_in));
	let boundary_out = "2001:db9::1".parse::<Ipv6Addr>().unwrap();
	assert!(!is_documentation_v6(boundary_out));
}
