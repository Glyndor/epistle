//! Unit tests for the trusted-proxy client IP resolution helper used by
//! the API and WebDAV listeners.

use std::net::{IpAddr, Ipv4Addr};

use axum::http::HeaderMap;

use super::effective;

fn trusted() -> Vec<crate::cidr::Cidr> {
	["10.0.0.0/8", "2001:db8:ffff::/48"]
		.into_iter()
		.map(|net| crate::cidr::Cidr::parse(net).unwrap())
		.collect()
}

fn headers(value: Option<&str>) -> HeaderMap {
	let mut headers = HeaderMap::new();
	if let Some(value) = value {
		headers.insert("x-forwarded-for", value.parse().unwrap());
	}
	headers
}

fn peer(text: &str) -> std::net::SocketAddr {
	text.parse().unwrap()
}

#[test]
fn untrusted_peer_returns_their_socket_address() {
	let trusted = trusted();
	assert_eq!(
		effective(&trusted, Some(peer("192.0.2.1:80")), &headers(None)),
		Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
	);
}

#[test]
fn trusted_peer_untrusted_forwarded_returns_the_forwarded_address() {
	let trusted = trusted();
	assert_eq!(
		effective(
			&trusted,
			Some(peer("10.0.0.1:80")),
			&headers(Some("198.51.100.1"))
		),
		Some("198.51.100.1".parse().unwrap())
	);
}

#[test]
fn chain_of_untrusted_hops_lands_on_the_leftmost_untrusted() {
	let trusted = trusted();
	assert_eq!(
		effective(
			&trusted,
			Some(peer("10.0.0.1:80")),
			&headers(Some("192.0.2.99, 198.51.100.1, 10.0.0.2"))
		),
		Some("198.51.100.1".parse().unwrap())
	);
}

#[test]
fn only_trusted_hops_keep_the_socket_address() {
	let trusted = trusted();
	assert_eq!(
		effective(
			&trusted,
			Some(peer("10.0.0.1:80")),
			&headers(Some("10.0.0.2, 10.0.0.3"))
		),
		Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
	);
}

#[test]
fn malformed_forwarded_discards_the_whole_header() {
	let trusted = trusted();
	assert_eq!(
		effective(
			&trusted,
			Some(peer("10.0.0.1:80")),
			&headers(Some("garbage, 198.51.100.1"))
		),
		Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
	);
	assert_eq!(
		effective(
			&trusted,
			Some(peer("10.0.0.1:80")),
			&headers(Some("198.51.100.1, garbage"))
		),
		Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
	);
	assert_eq!(
		effective(
			&trusted,
			Some(peer("10.0.0.1:80")),
			&headers(Some("198.51.100.1:80"))
		),
		Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
	);
}

#[test]
fn empty_trusted_always_returns_the_socket_address() {
	let trusted = Vec::new();
	assert_eq!(
		effective(
			&trusted,
			Some(peer("10.0.0.1:80")),
			&headers(Some("198.51.100.1"))
		),
		Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
	);
}

#[test]
fn missing_peer_returns_none() {
	let trusted = trusted();
	assert_eq!(effective(&trusted, None, &headers(None)), None);
	assert_eq!(
		effective(&trusted, None, &headers(Some("198.51.100.1"))),
		None
	);
}
