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

#[test]
fn address_records_come_before_the_mx() {
	// With both addresses configured, the A and AAAA must be the first
	// two records (in that order, A before AAAA) for the hostname, and
	// the MX for the served domain follows them. The whole point is to
	// make sure a sender that resolves the MX target finds addresses
	// already published instead of falling into a hard bounce window.
	let records = build_records(
		&["example.org".to_string()],
		"mail.example.org",
		&[],
		None,
		"v1",
		Services::default(),
		None,
		Some("203.0.113.10".parse().unwrap()),
		Some("2001:db8::10".parse().unwrap()),
	);
	assert!(
		records.len() >= 4,
		"expected A, AAAA, then MX, got {records:?}"
	);
	assert_eq!(records[0].record.kind, RecordKind::A);
	assert_eq!(records[0].record.name, "mail.example.org");
	assert_eq!(records[0].record.value, "203.0.113.10");
	assert_eq!(records[0].zone, "example.org");
	assert_eq!(records[1].record.kind, RecordKind::Aaaa);
	assert_eq!(records[1].record.name, "mail.example.org");
	assert_eq!(records[1].record.value, "2001:db8::10");
	assert_eq!(records[1].zone, "example.org");
	// The first MX (for the served domain) must come after the A and AAAA.
	let mx_index = records
		.iter()
		.position(|r| r.record.kind == RecordKind::Mx)
		.expect("MX emitted");
	assert!(
		mx_index >= 2,
		"MX must come after the A and AAAA, got MX at {mx_index}"
	);
	// And the address records are emitted once even with multiple served
	// domains; they belong to the hostname's zone, not the served zone.
	let a_count = records
		.iter()
		.filter(|r| r.record.kind == RecordKind::A)
		.count();
	let aaaa_count = records
		.iter()
		.filter(|r| r.record.kind == RecordKind::Aaaa)
		.count();
	assert_eq!(a_count, 1);
	assert_eq!(aaaa_count, 1);
}

#[test]
fn no_address_records_without_addresses() {
	// With neither address configured, no A or AAAA is emitted. The
	// existing per-domain records (SPF, MX, …) carry on as before.
	let records = build_records(
		&["example.org".to_string()],
		"mail.example.org",
		&[],
		None,
		"v1",
		Services::default(),
		None,
		None,
		None,
	);
	assert!(
		!records.iter().any(|r| r.record.kind == RecordKind::A),
		"no A without public_ipv4"
	);
	assert!(
		!records.iter().any(|r| r.record.kind == RecordKind::Aaaa),
		"no AAAA without public_ipv6"
	);
	// And the MX still comes first (no A/AAAA to prepend to it).
	let first = records
		.iter()
		.find(|r| r.record.kind == RecordKind::Mx)
		.expect("MX emitted");
	assert_eq!(first.zone, "example.org");
}

#[test]
fn only_ipv4_emits_only_a() {
	// With only IPv4 configured, the A is emitted and there is no
	// AAAA: receiving on IPv6 would fail silently otherwise, but
	// publishing an AAAA we cannot back would just mislead resolvers.
	let records = build_records(
		&["example.org".to_string()],
		"mail.example.org",
		&[],
		None,
		"v1",
		Services::default(),
		None,
		Some("203.0.113.10".parse().unwrap()),
		None,
	);
	assert!(
		records
			.iter()
			.any(|r| r.record.kind == RecordKind::A && r.record.value == "203.0.113.10"),
		"expected A with the configured address"
	);
	assert!(
		!records.iter().any(|r| r.record.kind == RecordKind::Aaaa),
		"no AAAA without public_ipv6"
	);
}
