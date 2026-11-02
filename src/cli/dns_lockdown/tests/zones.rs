//! `dns lockdown` with one `[[dns]]` entry per zone: the zone and the
//! provider come from the entry that holds the domain.

use std::process::ExitCode;

use super::base::{run, setup, zone_records};
use crate::dns::lockdown::tests::support::Zone;

const TWO_ZONES: &str = "\n[[dns]]\nprovider = 'cloudflare'\nzone = 'example.org'\ntoken_env = 'EPISTLE_TEST_UNSET_TOKEN'\n\n[[dns]]\nprovider = 'manual'\nzone = 'example.net'\n";

#[test]
fn a_domain_in_no_entry_zone_names_the_zones_there_are() {
	let setup = setup(TWO_ZONES, Zone::with(zone_records()));
	let outside = run(&setup, &["other.example", "--yes"]);
	assert_eq!(outside.code, ExitCode::FAILURE);
	assert_eq!(
		outside.err,
		"error: other.example is not in the zone of any [[dns]] entry: example.org, example.net\n"
	);
	assert_eq!(*setup.zone.writes.lock().unwrap(), 0);
}

#[test]
fn a_domain_in_a_manual_entry_is_left_to_the_operator_even_if_another_zone_publishes() {
	let setup = setup(TWO_ZONES, Zone::with(zone_records()));
	let manual = run(&setup, &["example.net", "--yes"]);
	assert_eq!(manual.code, ExitCode::SUCCESS, "{}", manual.err);
	assert!(
		manual.err.contains("no DNS provider is configured"),
		"{}",
		manual.err
	);
	assert_eq!(
		*setup.zone.writes.lock().unwrap(),
		0,
		"the other zone's provider must not be used for a manual zone"
	);
}

#[test]
fn an_entry_whose_credential_cannot_be_read_stops_before_any_write() {
	let setup = setup(TWO_ZONES, Zone::with(zone_records()));
	let unreadable = run(&setup, &["example.org", "--yes"]);
	assert_eq!(unreadable.code, ExitCode::FAILURE);
	assert!(
		unreadable
			.err
			.contains("credentials of the [[dns]] entry for example.org could not be read"),
		"{}",
		unreadable.err
	);
	assert_eq!(*setup.zone.writes.lock().unwrap(), 0);
}
