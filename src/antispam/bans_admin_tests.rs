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
