//! The `port addresses` item and the reason a failed boot unit gives.

use std::net::IpAddr;
use std::path::Path;

use super::base::{Fake, good, item};
use super::*;
use crate::cli::status::boot_area::host::Link;

fn config_on(addr: &str) -> Config {
	let text = format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"/data\"\ndomains = [\"example.org\"]\n\n[[listeners]]\nkind = \"smtp\"\naddr = \"{addr}\"\nport = 25\n"
	);
	Config::parse_text(&text, Path::new("/etc/epistle/mail.toml")).expect("config")
}

fn ip(text: &str) -> IpAddr {
	text.parse().expect("address")
}

fn judged(host: &mut Fake, addr: &str) -> crate::cli::status::report::Item {
	let report = check_with(host, &config_on(addr));
	item(&report, "port addresses").clone()
}

fn after(host: &mut Fake, units: &str) {
	host.system.insert(
		"show user@1001.service -p After --value".to_string(),
		units.to_string(),
	);
}

#[test]
fn the_wildcard_and_loopback_need_no_ordering() {
	for addr in ["0.0.0.0", "::", "127.0.0.1", "::1"] {
		let mut host = good();
		let found = judged(&mut host, addr);
		assert_eq!(found.status, Level::Ok, "{addr}: {found:?}");
		assert!(found.detail.contains("wildcard or loopback"), "{found:?}");
	}
}

#[test]
fn an_address_of_a_physical_interface_is_covered_by_the_network_wait() {
	let mut host = good();
	host.links.insert(ip("203.0.113.5"), Link::Physical);
	let found = judged(&mut host, "203.0.113.5");
	assert_eq!(found.status, Level::Ok, "{found:?}");
}

#[test]
fn a_wireguard_address_with_nothing_ordering_the_manager_is_a_warning_with_the_drop_in() {
	let mut host = good();
	host.links
		.insert(ip("10.0.0.1"), Link::WireGuard("wg0".to_string()));
	after(&mut host, "network.target sysinit.target");
	let found = judged(&mut host, "10.0.0.1");
	assert_eq!(found.status, Level::Warn, "{found:?}");
	for part in [
		"10.0.0.1 belongs to wg0",
		"wg-quick@wg0.service",
		"Cannot assign requested address",
		"After=wg-quick@wg0.service",
		"Wants=wg-quick@wg0.service",
		"/etc/systemd/system/user@1001.service.d/glyndor-epistle-address.conf",
		"daemon-reload",
	] {
		assert!(found.detail.contains(part), "{part}: {found:?}");
	}
}

#[test]
fn a_wireguard_address_the_manager_is_ordered_after_is_ok() {
	let mut host = good();
	host.links
		.insert(ip("10.0.0.1"), Link::WireGuard("wg0".to_string()));
	after(&mut host, "network.target wg-quick@wg0.service");
	let found = judged(&mut host, "10.0.0.1");
	assert_eq!(found.status, Level::Ok, "{found:?}");
}

#[test]
fn the_unit_of_another_interface_does_not_order_this_one() {
	let mut host = good();
	host.links
		.insert(ip("10.0.0.1"), Link::WireGuard("wg0".to_string()));
	after(&mut host, "wg-quick@wg1.service");
	let found = judged(&mut host, "10.0.0.1");
	assert_eq!(found.status, Level::Warn, "{found:?}");
}

#[test]
fn another_software_interface_names_the_interface_and_asks_for_its_unit() {
	let mut host = good();
	host.links
		.insert(ip("192.168.50.1"), Link::Virtual("br-mail".to_string()));
	let found = judged(&mut host, "192.168.50.1");
	assert_eq!(found.status, Level::Warn, "{found:?}");
	assert!(found.detail.contains("br-mail"), "{found:?}");
	assert!(
		found.detail.contains("After=<that unit>.service"),
		"{found:?}"
	);
}

#[test]
fn an_address_on_no_interface_is_a_warning() {
	let mut host = good();
	let found = judged(&mut host, "10.9.9.9");
	assert_eq!(found.status, Level::Warn, "{found:?}");
	assert!(found.detail.contains("no interface now"), "{found:?}");
}

#[test]
fn a_host_that_cannot_be_asked_is_not_blamed() {
	let mut host = good();
	host.links.insert(ip("10.0.0.1"), Link::Unknown);
	let found = judged(&mut host, "10.0.0.1");
	assert_eq!(found.status, Level::Ok, "{found:?}");
}

#[test]
fn a_failed_boot_unit_says_when_the_journal_shows_an_address_that_did_not_exist() {
	let mut host = good();
	host.user.insert(
		"show podup-epistle.service -p ActiveState -p Result".to_string(),
		"ActiveState=failed\nResult=exit-code".to_string(),
	);
	host.log = "podup: error: podman API error (HTTP 500): pasta failed with exit code 1:\nFailed to bind port 8025 (Cannot assign requested address) for option '-t 10.0.0.1/8025-8025:8025-8025'\n".to_string();
	let report = check_with(&mut host, &config_on("0.0.0.0"));
	let unit = item(&report, "boot unit");
	assert_eq!(unit.status, Level::Fail, "{unit:?}");
	assert!(
		unit.detail
			.contains("a published address did not exist yet"),
		"{unit:?}"
	);
	assert!(unit.detail.contains("port addresses"), "{unit:?}");
	assert!(unit.detail.contains("10.0.0.1/8025"), "{unit:?}");
}

#[test]
fn a_failed_boot_unit_without_that_line_keeps_the_plain_message() {
	let mut host = good();
	host.user.insert(
		"show podup-epistle.service -p ActiveState -p Result".to_string(),
		"ActiveState=failed\nResult=exit-code".to_string(),
	);
	host.log = "podup: error: something else\n".to_string();
	let report = check_with(&mut host, &config_on("0.0.0.0"));
	let unit = item(&report, "boot unit");
	assert!(!unit.detail.contains("did not exist yet"), "{unit:?}");
}
