use crate::config::Config;
use crate::dns::desired;
use crate::dns::listing::{Row, is_host_record, of_domains, skipped_rows};
use crate::dns::provider::{DnsRecord, RecordKind};
use crate::dns::records::PublishRecord;
use crate::dns::skip::{SkipGroup, SkippedGroup};

fn entry(name: &str, kind: RecordKind) -> PublishRecord {
	PublishRecord {
		zone: "example.org".to_string(),
		record: DnsRecord::new(name, kind, "value", 3600),
	}
}

fn config() -> Config {
	toml::from_str(
		"hostname = 'Mail.Example.Org'\ndata_dir = '/var/lib/mail'\n\
		 domains = ['example.org', 'example.net']\n\
		 public_ipv4 = '192.0.2.1'\npublic_ipv6 = '2001:db8::1'\n",
	)
	.expect("config")
}

#[test]
fn the_records_of_the_mail_host_are_told_from_the_records_of_a_domain() {
	let host = "mail.example.org";
	assert!(is_host_record(&entry(host, RecordKind::A), host));
	assert!(is_host_record(&entry(host, RecordKind::Aaaa), host));
	assert!(is_host_record(
		&entry("_25._tcp.mail.example.org", RecordKind::Tlsa),
		host
	));
	// Case does not tell a name from itself.
	assert!(is_host_record(
		&entry("MAIL.example.org", RecordKind::A),
		host
	));
	assert!(is_host_record(
		&entry(host, RecordKind::A),
		"Mail.Example.Org"
	));
	// A domain's own records are not the host's, whatever their name.
	assert!(!is_host_record(&entry("example.org", RecordKind::Mx), host));
	assert!(!is_host_record(&entry(host, RecordKind::Txt), host));
	assert!(!is_host_record(&entry(host, RecordKind::Mx), host));
	assert!(!is_host_record(
		&entry("other.example.org", RecordKind::A),
		host
	));
	assert!(!is_host_record(
		&entry("_25._tcp.other.example.org", RecordKind::Tlsa),
		host
	));
}

#[test]
fn the_full_listing_is_the_set_the_command_prints() {
	let config = config();
	let all = of_domains(&config, &config.domains, true).expect("listing");
	let printed = desired::from_config(&config).expect("desired");
	assert_eq!(all.records, printed.records);
	assert!(all.complete);
	assert!(
		all.records
			.iter()
			.any(|entry| is_host_record(entry, &config.hostname))
	);
}

#[test]
fn without_the_host_only_the_records_of_the_domains_remain() {
	let config = config();
	let domains = vec!["example.net".to_string()];
	let own = of_domains(&config, &domains, false).expect("listing");
	assert!(!own.records.is_empty());
	assert!(
		own.records
			.iter()
			.all(|entry| !is_host_record(entry, &config.hostname))
	);
	assert!(own.records.iter().all(|entry| entry.zone == "example.net"));
	let with = of_domains(&config, &domains, true).expect("listing");
	assert_eq!(
		with.records.len(),
		own.records.len() + 2,
		"the two address records of the host"
	);
}

#[test]
fn no_domain_and_no_host_is_an_empty_listing() {
	let config = config();
	let none = of_domains(&config, &[], false).expect("listing");
	assert!(none.records.is_empty());
	assert!(none.complete);
}

#[test]
fn a_row_carries_the_four_fields_the_command_prints() {
	let row = Row::of(&entry("example.org", RecordKind::Mx));
	assert_eq!(
		serde_json::to_value(&row).expect("row"),
		serde_json::json!({"name": "example.org", "ttl": 3600, "type": "MX", "value": "value"})
	);
}

/// A group that holds only the mail host's record says nothing to a caller
/// that does not see the host, and a group with domain records counts them.
#[test]
fn a_skipped_group_is_counted_for_what_the_caller_sees() {
	let host = "mail.example.org";
	let groups = vec![
		SkippedGroup {
			group: SkipGroup::Tlsa,
			records: vec![entry("_25._tcp.mail.example.org", RecordKind::Tlsa)],
		},
		SkippedGroup {
			group: SkipGroup::MtaSts,
			records: vec![
				entry("_mta-sts.example.org", RecordKind::Txt),
				entry("mta-sts.example.org", RecordKind::Cname),
			],
		},
	];
	let names = |rows: Vec<crate::dns::listing::Skipped>| -> Vec<(&'static str, usize)> {
		rows.into_iter()
			.map(|row| (row.group, row.records))
			.collect()
	};
	let own = skipped_rows(&groups, |entry| !is_host_record(entry, host));
	assert_eq!(names(own), [("mta-sts", 2)]);
	let all = skipped_rows(&groups, |_| true);
	assert_eq!(names(all), [("tlsa", 1), ("mta-sts", 2)]);
}
