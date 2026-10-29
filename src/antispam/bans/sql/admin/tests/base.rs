//! The pure matching rules behind the allow list and network bans.

use super::*;

fn ip(text: &str) -> IpAddr {
	text.parse().expect("ip")
}

fn entries(list: &[&str]) -> Vec<String> {
	list.iter().map(|s| s.to_string()).collect()
}

#[test]
fn an_allow_entry_covers_its_network_and_nothing_else() {
	let list = entries(&["203.0.113.0/24", "198.51.100.7/32", "2001:db8::/32"]);
	assert!(is_allowed(ip("203.0.113.200"), &list));
	assert!(is_allowed(ip("198.51.100.7"), &list));
	assert!(is_allowed(ip("2001:db8::5"), &list));
	assert!(!is_allowed(ip("203.0.114.1"), &list));
	assert!(!is_allowed(ip("198.51.100.8"), &list));
	assert!(!is_allowed(ip("2001:db9::1"), &list));
	assert!(!is_allowed(ip("203.0.113.1"), &[]));
}

#[test]
fn a_corrupt_allow_entry_never_matches() {
	assert!(!is_allowed(ip("203.0.113.1"), &entries(&["garbage", ""])));
}

#[test]
fn a_ban_applies_to_its_address_or_a_containing_network() {
	assert!(ban_applies("ip:203.0.113.9", ip("203.0.113.9")));
	assert!(!ban_applies("ip:203.0.113.9", ip("203.0.113.10")));
	assert!(ban_applies("cidr:203.0.113.0/24", ip("203.0.113.10")));
	assert!(!ban_applies("cidr:203.0.113.0/24", ip("203.0.114.10")));
	// Account bans never apply to an address, and junk does not panic.
	assert!(!ban_applies("account:alice", ip("203.0.113.9")));
	assert!(!ban_applies("cidr:garbage", ip("203.0.113.9")));
}

#[test]
fn only_ip_subjects_name_an_address() {
	assert_eq!(ip_of_subject("ip:2001:db8::1"), Some(ip("2001:db8::1")));
	assert_eq!(ip_of_subject("account:alice"), None);
	assert_eq!(ip_of_subject("cidr:10.0.0.0/8"), None);
	assert_eq!(ip_of_subject("ip:not-an-ip"), None);
}

#[test]
fn remove_takes_every_subject_ban_list_prints() {
	for (spec, subjects, shown) in [
		(
			"pair:Alice@Example.org|10.0.2.15",
			vec!["pair:alice@example.org|10.0.2.15"],
			"pair:alice@example.org|10.0.2.15",
		),
		(
			"pair:alice|2001:db8:1:2::",
			vec!["pair:alice|2001:db8:1:2::"],
			"pair:alice|2001:db8:1:2::",
		),
		(
			"pair:alice|unknown",
			vec!["pair:alice|unknown"],
			"pair:alice|unknown",
		),
		("account:Alice", vec!["account:alice"], "account:alice"),
		(
			"ip:203.0.113.9",
			vec!["ip:203.0.113.9", "ip:203.0.113.9"],
			"203.0.113.9",
		),
		(
			"cidr:203.0.113.0/24",
			vec!["cidr:203.0.113.0/24"],
			"203.0.113.0/24",
		),
		(
			"2001:db8::5",
			vec!["ip:2001:db8::5", "ip:2001:db8::"],
			"2001:db8::5",
		),
	] {
		let target = UnbanTarget::parse(spec).unwrap_or_else(|e| panic!("{spec}: {e}"));
		assert_eq!(target.subjects(), subjects, "{spec}");
		assert_eq!(target.to_string(), shown, "{spec}");
	}
}

#[test]
fn a_pair_named_by_its_parts_is_the_subject_the_listeners_ban() {
	let pair = UnbanTarget::pair("Alice", Some(ip("2001:db8:1:2::77"))).expect("pair");
	assert_eq!(
		pair.to_string(),
		subject_pair("alice", Some(ip("2001:db8:1:2::5")))
	);
	assert_eq!(
		UnbanTarget::parse("pair:alice|2001:db8:1:2::77").expect("parse"),
		pair
	);
}

#[test]
fn remove_refuses_a_malformed_subject_by_name() {
	for (spec, reason) in [
		("pair:alice", "is not a pair"),
		("pair:alice|nope", "is not a pair"),
		("pair:|10.0.2.15", "the login is empty"),
		("pair:al ice|10.0.2.15", "contains whitespace"),
		("account:", "the login is empty"),
		("alice", "or name an account ban as `ban list` prints it"),
		("0.0.0.0/0", "refusing to ban every address"),
	] {
		let error = UnbanTarget::parse(spec).expect_err(spec);
		assert!(error.contains(reason), "{spec}: {error}");
	}
}
