use super::*;

fn zone_of(hostname: &str, domains: &[&str]) -> String {
	let domains: Vec<String> = domains.iter().map(|d| d.to_string()).collect();
	let records = build_records(
		&domains,
		hostname,
		&[],
		None,
		"v1",
		Services::default(),
		None,
		Some("203.0.113.10".parse().unwrap()),
		None,
	);
	records
		.iter()
		.find(|r| r.record.kind == RecordKind::A)
		.map(|r| r.zone.clone())
		.expect("an A record is emitted when public_ipv4 is set")
}

#[test]
fn address_records_land_in_the_configured_domain_that_contains_the_hostname() {
	// The provider credentials cover the configured zone, so a hostname two
	// labels below it must still publish into that zone, not into a
	// non-existent intermediate one.
	assert_eq!(
		zone_of("mx.mail.example.org", &["example.org"]),
		"example.org"
	);
	// The longest configured match wins when the zones nest.
	assert_eq!(
		zone_of("mx.mail.example.org", &["example.org", "mail.example.org"]),
		"mail.example.org"
	);
	// A hostname at the apex of a configured domain is in that zone.
	assert_eq!(zone_of("example.org", &["example.org"]), "example.org");
}

#[test]
fn address_records_fall_back_to_the_parent_of_an_unconfigured_hostname() {
	// A hostname outside every configured domain keeps the old rule: the
	// zone is whatever follows the first label. A look-alike suffix without
	// the dot boundary (`notexample.org`) does not count as a match.
	assert_eq!(zone_of("mail.other.net", &["example.org"]), "other.net");
	assert_eq!(
		zone_of("mail.notexample.org", &["example.org"]),
		"notexample.org"
	);
}
