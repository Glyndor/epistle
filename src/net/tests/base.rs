use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

#[test]
fn v4_mapped_v6_becomes_plain_v4() {
	let addr: SocketAddr = "[::ffff:192.0.2.7]:25".parse().expect("parse v4-mapped");
	let canonical = super::canonical_peer(addr);
	assert_eq!(canonical.ip(), IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)));
	assert_eq!(canonical.port(), 25);
}

#[test]
fn plain_v4_is_unchanged() {
	let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 25));
	let canonical = super::canonical_peer(addr);
	assert_eq!(
		canonical,
		SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 25))
	);
}

#[test]
fn plain_v6_is_unchanged() {
	let addr = SocketAddr::V6(SocketAddrV6::new(
		Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
		25,
		0,
		0,
	));
	let canonical = super::canonical_peer(addr);
	assert_eq!(
		canonical,
		SocketAddr::V6(SocketAddrV6::new(
			Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
			25,
			0,
			0,
		))
	);
}

#[test]
fn v4_unspecified_is_still_v4() {
	let addr: SocketAddr = "[::ffff:0.0.0.0]:443".parse().expect("parse v4-mapped any");
	let canonical = super::canonical_peer(addr);
	assert_eq!(
		canonical,
		SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 443))
	);
}
