//! `status` reports the server's own addresses against the DNS blocklists,
//! from the state the running server keeps.

use std::net::IpAddr;

use super::super::own_ip::items_at;
use crate::cli::status::report::Level;
use crate::cli::status::test_support::ctx;
use crate::config::Config;
use crate::dnsbl::own::{self, Check, State, Status};

const V4: &str = "93.184.216.34";
const NOW: u64 = 10_000;

fn config(dir: &std::path::Path, extra: &str) -> Config {
	let extra = format!("public_ipv4 = \"{V4}\"\ndnsbl_zones = [\"zen.spamhaus.org\"]\n{extra}");
	ctx(dir, &extra).config.expect("config")
}

fn v4() -> IpAddr {
	V4.parse().expect("ip")
}

fn record(config: &Config, status: Status, at: u64) {
	let mut state = own::load(&config.data_dir)
		.expect("load")
		.unwrap_or_default();
	let delist_url = own::delist_url("zen.spamhaus.org").map(str::to_string);
	state.apply(Check {
		address: v4(),
		status: status.clone(),
		delist_url: matches!(status, Status::Listed { .. })
			.then_some(delist_url)
			.flatten(),
		checked_at: at,
	});
	own::save(&config.data_dir, &state).expect("save");
}

#[test]
fn a_listed_address_is_a_warning_with_the_zone_and_the_page() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path(), "");
	record(
		&config,
		Status::Listed {
			zone: "zen.spamhaus.org".into(),
		},
		NOW,
	);
	let found = items_at(&config, NOW + 5);
	assert_eq!(found.len(), 1, "{found:?}");
	assert_eq!(found[0].status, Level::Warn);
	assert!(
		found[0].detail.contains("LISTED in zen.spamhaus.org"),
		"{found:?}"
	);
	assert!(
		found[0]
			.detail
			.contains("https://check.spamhaus.org/listed/"),
		"{found:?}"
	);
}

#[test]
fn a_clean_address_is_ok() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path(), "");
	record(&config, Status::NotListed, NOW);
	let found = items_at(&config, NOW + 5);
	assert_eq!(found[0].status, Level::Ok, "{found:?}");
	assert!(found[0].detail.contains("not listed"), "{found:?}");
}

#[test]
fn an_unknown_result_is_a_warning_never_ok() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path(), "");
	record(&config, Status::Unknown, NOW);
	let found = items_at(&config, NOW + 5);
	assert_eq!(found[0].status, Level::Warn, "{found:?}");
	assert!(found[0].detail.contains("UNKNOWN"), "{found:?}");
}

#[test]
fn an_old_clean_answer_is_not_trusted() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path(), "");
	record(&config, Status::NotListed, NOW);
	let found = items_at(&config, NOW + 3 * 3_600 + 1);
	assert_eq!(found[0].status, Level::Warn, "{found:?}");
	assert!(
		found[0].detail.contains("is the server running"),
		"{found:?}"
	);
}

#[test]
fn before_the_first_check_the_line_says_so() {
	let dir = tempfile::tempdir().expect("tempdir");
	let found = items_at(&config(dir.path(), ""), NOW);
	assert_eq!(found[0].status, Level::Ok, "{found:?}");
	assert!(found[0].detail.contains("not checked yet"), "{found:?}");
}

#[test]
fn switched_off_or_without_zones_or_addresses_nothing_is_reported() {
	let dir = tempfile::tempdir().expect("tempdir");
	let off = config(dir.path(), "[own_ip_blocklist]\nenabled = false\n");
	assert!(items_at(&off, NOW).is_empty());
	let dir = tempfile::tempdir().expect("tempdir");
	let bare = ctx(dir.path(), "public_ipv4 = \"93.184.216.34\"\n")
		.config
		.expect("config");
	assert!(items_at(&bare, NOW).is_empty());
	let dir = tempfile::tempdir().expect("tempdir");
	let no_ip = ctx(dir.path(), "dnsbl_zones = [\"zen.spamhaus.org\"]\n")
		.config
		.expect("config");
	assert!(items_at(&no_ip, NOW).is_empty());
}

#[test]
fn an_unreadable_state_is_a_warning() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path(), "");
	std::fs::write(own::path(&config.data_dir), b"garbage").expect("write");
	let found = items_at(&config, NOW);
	assert_eq!(found[0].status, Level::Warn, "{found:?}");
	let _ = State::default();
}
