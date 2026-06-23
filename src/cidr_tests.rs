//! Tests for CIDR parsing and containment.

use super::*;

fn ip(text: &str) -> IpAddr {
	text.parse().expect("ip")
}

#[test]
fn ipv4_containment_in_and_out() {
	let cidr = Cidr::parse("203.0.113.0/24").expect("cidr");
	assert!(cidr.contains(ip("203.0.113.0")));
	assert!(cidr.contains(ip("203.0.113.1")));
	assert!(cidr.contains(ip("203.0.113.255")));
	assert!(!cidr.contains(ip("203.0.114.0")));
	assert!(!cidr.contains(ip("203.0.112.255")));
}

#[test]
fn ipv4_bare_address_is_host_route() {
	let cidr = Cidr::parse("198.51.100.7").expect("cidr");
	assert!(cidr.contains(ip("198.51.100.7")));
	assert!(!cidr.contains(ip("198.51.100.8")));
}

#[test]
fn ipv6_containment_in_and_out() {
	let cidr = Cidr::parse("2001:db8::/32").expect("cidr");
	assert!(cidr.contains(ip("2001:db8::1")));
	assert!(cidr.contains(ip("2001:db8:ffff::ffff")));
	assert!(!cidr.contains(ip("2001:db9::1")));
}

#[test]
fn ipv6_bare_address_is_host_route() {
	let cidr = Cidr::parse("2001:db8::1").expect("cidr");
	assert!(cidr.contains(ip("2001:db8::1")));
	assert!(!cidr.contains(ip("2001:db8::2")));
}

#[test]
fn cross_family_never_contained() {
	let v4 = Cidr::parse("203.0.113.0/24").expect("cidr");
	assert!(!v4.contains(ip("2001:db8::1")));
	let v6 = Cidr::parse("2001:db8::/32").expect("cidr");
	assert!(!v6.contains(ip("203.0.113.1")));
}

#[test]
fn zero_prefix_matches_whole_family() {
	let cidr = Cidr::parse("0.0.0.0/0").expect("cidr");
	assert!(cidr.contains(ip("1.2.3.4")));
	assert!(cidr.contains(ip("255.255.255.255")));
	assert!(!cidr.contains(ip("2001:db8::1")));
}

#[test]
fn host_bits_in_spec_are_masked_off() {
	// 203.0.113.55/24 is sloppy but should behave as 203.0.113.0/24.
	let cidr = Cidr::parse("203.0.113.55/24").expect("cidr");
	assert!(cidr.contains(ip("203.0.113.0")));
	assert!(cidr.contains(ip("203.0.113.200")));
	assert!(!cidr.contains(ip("203.0.114.1")));
}

#[test]
fn bad_cidr_rejected() {
	assert!(Cidr::parse("").is_none());
	assert!(Cidr::parse("not-an-ip").is_none());
	assert!(Cidr::parse("203.0.113.0/33").is_none());
	assert!(Cidr::parse("203.0.113.0/-1").is_none());
	assert!(Cidr::parse("203.0.113.0/abc").is_none());
	assert!(Cidr::parse("2001:db8::/129").is_none());
	assert!(Cidr::parse("203.0.113.256").is_none());
	assert!(Cidr::parse("203.0.113.0/").is_none());
}
