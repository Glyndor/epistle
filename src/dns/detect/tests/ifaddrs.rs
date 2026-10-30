//! The interface walk behind `detect()`: how one socket address becomes an IP,
//! and what the live kernel list contains.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use nix::sys::socket::SockaddrStorage;

use super::{read_interface_addresses, socket_ip};

fn storage(text: &str) -> SockaddrStorage {
	let addr: SocketAddr = text.parse().expect("socket address");
	SockaddrStorage::from(addr)
}

#[test]
fn ipv4_socket_address_keeps_its_octets() {
	assert_eq!(
		socket_ip(&storage("192.0.2.7:0")),
		Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)))
	);
}

#[test]
fn ipv6_socket_address_keeps_its_segments() {
	assert_eq!(
		socket_ip(&storage("[2001:db8::1:2]:0")),
		Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 1, 2)))
	);
}

#[test]
fn ipv4_mapped_ipv6_is_skipped() {
	assert_eq!(socket_ip(&storage("[::ffff:192.0.2.7]:0")), None);
}

#[test]
fn live_interface_list_includes_the_loopback_addresses() {
	let addresses = read_interface_addresses().expect("getifaddrs");
	assert!(
		addresses.contains(&IpAddr::V4(Ipv4Addr::LOCALHOST)),
		"loopback 127.0.0.1 missing from {} addresses",
		addresses.len()
	);
	assert!(
		addresses
			.iter()
			.all(|ip| !matches!(ip, IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some())),
		"an IPv4-mapped IPv6 address leaked into the list"
	);
}
