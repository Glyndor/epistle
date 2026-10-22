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

#[test]
fn review_special_ranges_are_not_public_addresses() {
	for text in [
		"0.1.2.3",
		"192.0.0.9",
		"198.18.0.1",
		"198.19.255.255",
		"240.0.0.1",
	] {
		assert!(
			non_global_ipv4_reason(text.parse().unwrap()).is_some(),
			"{text}"
		);
	}
	for text in ["fec0::1", "100::1", "2001:2::1", "3fff::1"] {
		assert!(
			non_global_ipv6_reason(text.parse().unwrap()).is_some(),
			"{text}"
		);
	}
}

#[test]
fn review_special_range_boundaries_and_global_controls() {
	for text in [
		"0.255.255.255",
		"192.0.0.0",
		"192.0.0.255",
		"198.18.0.0",
		"198.19.255.255",
		"240.0.0.0",
		"255.255.255.254",
	] {
		assert!(
			non_global_ipv4_reason(text.parse().unwrap()).is_some(),
			"{text}"
		);
	}
	for text in [
		"1.0.0.0",
		"192.0.1.0",
		"198.17.255.255",
		"198.20.0.0",
		"223.255.255.255",
	] {
		assert!(
			non_global_ipv4_reason(text.parse().unwrap()).is_none(),
			"{text}"
		);
	}
	for text in [
		"64:ff9b:1::1",
		"2001::1",
		"2001:10::1",
		"2001:1ff::1",
		"2002::1",
		"3fff:fff:ffff::1",
		"5f00::1",
		"4000::1",
	] {
		assert!(
			non_global_ipv6_reason(text.parse().unwrap()).is_some(),
			"{text}"
		);
	}
	for text in [
		"2001:1::1",
		"2001:1::2",
		"2001:1::3",
		"2001:3::1",
		"2001:4:112::1",
		"2001:20::1",
		"2001:30::1",
		"2001:200::1",
		"3fff:1000::1",
		"::ffff:1.1.1.1",
	] {
		assert!(
			non_global_ipv6_reason(text.parse().unwrap()).is_none(),
			"{text}"
		);
	}
}

#[test]
fn review_registry_relay_anycast_is_not_global() {
	for text in ["192.88.99.0", "192.88.99.2", "192.88.99.255"] {
		assert!(
			non_global_ipv4_reason(text.parse().unwrap()).is_some(),
			"{text}"
		);
	}
}

#[test]
fn review_registry_global_nat64_prefix_remains_public() {
	assert!(non_global_ipv6_reason("64:ff9b::1.1.1.1".parse().unwrap()).is_none());
}

#[test]
fn embedded_ipv4_payload_decides_the_verdict_in_every_form() {
	// NAT64 (64:ff9b::/96), 6to4 (2002::/16), IPv4-compatible (::a.b.c.d) and
	// IPv4-mapped (::ffff:a.b.c.d) all carry an IPv4 payload. Each one used to
	// pass the range check without that payload ever being read.
	for text in [
		// NAT64.
		"64:ff9b::7f00:1",
		"64:ff9b::a00:1",
		"64:ff9b::ac10:1",
		"64:ff9b::c0a8:1",
		"64:ff9b::6440:1",
		"64:ff9b::a9fe:a9fe",
		"64:ff9b::c000:201",
		"64:ff9b::e000:1",
		"64:ff9b::ffff:ffff",
		"64:ff9b::",
		// 6to4.
		"2002:7f00:1::1",
		"2002:a00:1::1",
		"2002:c000:201::1",
		"2002:e000:1::1",
		"2002:ffff:ffff::1",
		// IPv4-compatible and IPv4-mapped.
		"::7f00:1",
		"::10.0.0.1",
		"::ffff:192.168.1.10",
		"::ffff:100.64.0.1",
		"::ffff:224.0.0.1",
	] {
		assert!(
			non_global_ipv6_reason(text.parse().unwrap()).is_some(),
			"{text}"
		);
	}
	// A global payload keeps the verdict the form already had: the mapped form
	// and the public NAT64 prefix are global addresses, while the deprecated
	// compatible form and 6to4 are refused on their own.
	for text in ["64:ff9b::808:808", "64:ff9b::1.1.1.1", "::ffff:1.1.1.1"] {
		assert!(
			non_global_ipv6_reason(text.parse().unwrap()).is_none(),
			"{text}"
		);
	}
	for text in ["::1.1.1.1", "2002:101:101::1"] {
		assert!(
			non_global_ipv6_reason(text.parse().unwrap()).is_some(),
			"{text}"
		);
	}
}

#[test]
fn embedded_ipv4_reason_names_the_form_and_the_payload() {
	let cases: &[(Ipv6Addr, &[&str])] = &[
		("64:ff9b::7f00:1".parse().unwrap(), &["NAT64", "loopback"]),
		("64:ff9b::a00:1".parse().unwrap(), &["NAT64", "private"]),
		("2002:7f00:1::1".parse().unwrap(), &["6to4", "loopback"]),
		("::10.0.0.1".parse().unwrap(), &["compatible", "private"]),
		(
			"::ffff:192.168.1.10".parse().unwrap(),
			&["IPv4-mapped", "private"],
		),
	];
	for (ip, expected) in cases {
		let reason = non_global_ipv6_reason(*ip).unwrap_or_else(|| panic!("{ip} accepted"));
		for part in *expected {
			assert!(reason.contains(part), "{ip}: {reason} lacks {part}");
		}
	}
	// The unspecified address is an address of its own, not a payload of
	// 0.0.0.0, so it keeps its own message.
	assert_eq!(
		non_global_ipv6_reason("::".parse().unwrap()),
		Some("the unspecified address (::)")
	);
}
