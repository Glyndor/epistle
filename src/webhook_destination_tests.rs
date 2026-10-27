//! The destination policy of the webhook client.

use super::*;
use std::str::FromStr;

fn private(ip: &str) -> bool {
	is_private(ip.parse().expect("address"))
}

#[test]
fn the_private_ranges_are_private() {
	for address in [
		"127.0.0.1",
		"127.1.2.3",
		"10.0.0.1",
		"172.16.0.1",
		"172.31.255.255",
		"192.168.0.1",
		"169.254.169.254",
		"0.0.0.0",
		"255.255.255.255",
		"100.64.0.1",
		"::1",
		"::",
		"fe80::1",
		"fc00::1",
		"fd12:3456::1",
		"::ffff:127.0.0.1",
		"::ffff:10.0.0.1",
	] {
		assert!(private(address), "{address} must be private");
	}
}

#[test]
fn the_public_ranges_are_not_private() {
	for address in [
		"8.8.8.8",
		"1.1.1.1",
		"203.0.113.9",
		"2001:db8::1",
		"2606:4700::1",
	] {
		assert!(!private(address), "{address} must not be private");
	}
}

#[test]
fn the_legacy_notations_spell_the_address_they_name() {
	assert_eq!(
		legacy_ipv4("2130706433"),
		Some("127.0.0.1".parse().unwrap())
	);
	assert_eq!(
		legacy_ipv4("0177.0.0.1"),
		Some("127.0.0.1".parse().unwrap())
	);
	assert_eq!(
		legacy_ipv4("0x7f000001"),
		Some("127.0.0.1".parse().unwrap())
	);
	assert_eq!(legacy_ipv4("127.0.0.1"), Some("127.0.0.1".parse().unwrap()));
	assert_eq!(legacy_ipv4("example.test"), None);
	assert_eq!(legacy_ipv4(""), None);
}

#[test]
fn a_private_destination_is_refused() {
	for url in [
		"http://127.0.0.1/hook",
		"http://[::1]/hook",
		"http://10.0.0.1/hook",
		"http://172.16.0.1/hook",
		"http://192.168.0.1/hook",
		"http://169.254.169.254/latest/meta-data/",
		"http://[::ffff:127.0.0.1]/hook",
		"http://2130706433/hook",
		"http://0177.0.0.1/hook",
		"http://0x7f000001/hook",
		"http://a@127.0.0.1/hook",
		"http://127.0.0.1@example.test/hook",
	] {
		assert!(check_url(url, false).is_err(), "{url} must be refused");
	}
}

#[test]
fn a_public_destination_is_accepted() {
	for url in [
		"https://hooks.example/mail",
		"http://hooks.example/mail",
		"https://8.8.8.8/mail",
		"https://[2606:4700::1111]/mail",
	] {
		assert!(check_url(url, false).is_ok(), "{url} must be accepted");
	}
}

#[test]
fn a_private_destination_is_accepted_when_it_is_allowed() {
	assert!(check_url("http://127.0.0.1/hook", true).is_ok());
}

#[test]
fn a_url_the_transport_refuses_is_left_to_it() {
	// Neither of these carries HTTP, so the transport refuses them when
	// the event is sent; the policy has nothing to say about them.
	for url in [
		"file:///etc/passwd",
		"gopher://127.0.0.1:9/_test",
		"not a url",
	] {
		assert!(
			check_url(url, false).is_ok(),
			"{url} must be left to the transport"
		);
	}
}

#[tokio::test]
async fn the_resolver_keeps_the_private_addresses_out() {
	let resolver = DestinationResolver {
		allow_private: false,
	};
	let name = Name::from_str("localhost").expect("name");
	// Either the name resolves to no address the client may reach, or the
	// host does not resolve it at all: never to a private address.
	if let Ok(addresses) = resolver.resolve(name).await {
		let addresses: Vec<SocketAddr> = addresses.collect();
		assert!(addresses.is_empty(), "{addresses:?}");
	}
}

#[tokio::test]
async fn the_resolver_keeps_the_private_addresses_when_they_are_allowed() {
	let resolver = DestinationResolver {
		allow_private: true,
	};
	let name = Name::from_str("localhost").expect("name");
	// The name may not resolve on this host; when it does, the address
	// comes back.
	if let Ok(addresses) = resolver.resolve(name).await {
		let addresses: Vec<SocketAddr> = addresses.collect();
		assert!(!addresses.is_empty());
	}
}
