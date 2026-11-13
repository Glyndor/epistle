//! A domain that sends nothing or accepts nothing changes what the publisher
//! keeps true: whole runs against a zone in memory, from a `full` domain to
//! each role and back. Nothing reaches a real DNS service.

use std::path::Path;

use super::run::{Harness, publish, read};
use super::support::{holds, rec, txt};
use super::*;
use crate::config::Config;
use crate::dns::lockdown::tests::support::{Zone, a};
use crate::dns::records::{DomainDkim, ServiceRecords, build_records_for_roles};

const DKIM: &str = "v=DKIM1; k=ed25519; p=AAAA";

fn config_in(dir: &Path, extra: &str) -> Config {
	toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = {dir:?}\ndomains = ['example.org']\n{extra}\n\
		 [dns]\nprovider = 'cloudflare'\nzone = 'example.org'\ntoken = 'inline-token'\n"
	))
	.expect("config")
}

/// The same data directory with another configuration: the role changed.
fn reconfigured(h: &Harness, extra: &str) -> Harness {
	Harness {
		_dir: tempfile::tempdir().expect("directory"),
		config: config_in(&h.config.data_dir, extra),
	}
}

fn harness_with(extra: &str) -> Harness {
	let dir = tempfile::tempdir().expect("directory");
	let config = config_in(dir.path(), extra);
	Harness { _dir: dir, config }
}

/// What `config` wants in DNS, with a DKIM key at selector `sel`, filtered
/// the way [`crate::dns::desired`] filters it.
fn wanted(config: &Config) -> Vec<DnsRecord> {
	let records = build_records_for_roles(
		&config.domains,
		&config.hostname,
		(&[("sel".to_string(), DKIM.to_string())], &DomainDkim::new()),
		(None, "1", ServiceRecords::default()),
		(None, None, None),
		&config.roles(),
	);
	crate::dns::skip::split_records(records, &config.skip_set())
		.0
		.into_iter()
		.map(|r| r.record)
		.collect()
}

fn run(h: &Harness, zone: &Zone) {
	let report = publish(h, zone, read(h, zone, &wanted(&h.config)));
	assert!(report.failure.is_none(), "{:?}", report.failure);
}

fn of(zone: &Zone, name: &str, kind: RecordKind) -> Vec<String> {
	zone.snapshot()
		.into_iter()
		.filter(|r| r.name == name && r.kind == kind)
		.map(|r| r.value)
		.collect()
}

fn dkim() -> DnsRecord {
	txt("sel._domainkey.example.org", DKIM)
}

fn mta_sts() -> DnsRecord {
	txt("_mta-sts.example.org", "v=STSv1; id=1")
}

/// A zone `full` already published.
fn published() -> (Harness, Zone) {
	let h = harness_with("");
	let zone = Zone::with(vec![]);
	run(&h, &zone);
	let now = zone.snapshot();
	assert!(holds(&now, &dkim()), "a full domain publishes its key");
	assert_eq!(
		of(&zone, "example.org", RecordKind::Txt),
		vec!["v=spf1 mx -all".to_string()]
	);
	(h, zone)
}

#[test]
fn a_receive_only_role_retires_the_key_and_nulls_the_spf() {
	let (h, zone) = published();
	let h = reconfigured(&h, "receive_only_domains = ['example.org']\n");
	run(&h, &zone);
	let now = zone.snapshot();
	assert!(
		!holds(&now, &dkim()),
		"the key is retired through the ledger"
	);
	assert_eq!(
		of(&zone, "example.org", RecordKind::Txt),
		vec!["v=spf1 -all".to_string()],
		"one SPF, the null one"
	);
	assert_eq!(
		of(&zone, "example.org", RecordKind::Mx),
		vec!["10 mail.example.org".to_string()],
		"it still receives"
	);
	assert!(holds(&now, &mta_sts()), "receiving keeps its policy");
	let dmarc = of(&zone, "_dmarc.example.org", RecordKind::Txt);
	assert!(dmarc[0].contains("p=reject"), "{dmarc:?}");
	assert!(
		dmarc[0].contains("rua=mailto:postmaster@example.org"),
		"{dmarc:?}"
	);
}

#[test]
fn a_disabled_domain_gets_the_null_mx_and_loses_every_receiving_record() {
	let (h, zone) = published();
	let h = reconfigured(&h, "disabled_domains = ['example.org']\n");
	run(&h, &zone);
	let now = zone.snapshot();
	assert_eq!(
		of(&zone, "example.org", RecordKind::Mx),
		vec!["0 .".to_string()],
		"the null MX replaces the host, and it is the only MX"
	);
	assert_eq!(
		of(&zone, "example.org", RecordKind::Txt),
		vec!["v=spf1 -all".to_string()]
	);
	assert!(!holds(&now, &dkim()));
	assert!(!holds(&now, &mta_sts()));
	let dmarc = of(&zone, "_dmarc.example.org", RecordKind::Txt);
	assert!(
		dmarc[0].contains("p=reject") && !dmarc[0].contains("rua="),
		"{dmarc:?}"
	);
}

#[test]
fn a_second_run_of_a_disabled_domain_changes_nothing() {
	let h = harness_with("disabled_domains = ['example.org']\n");
	let zone = Zone::with(vec![]);
	run(&h, &zone);
	let again = read(&h, &zone, &wanted(&h.config));
	assert!(!again.changes(), "{:#?}", again.zones[0].plan.entries);
}

#[test]
fn enabling_the_domain_again_puts_the_records_back() {
	let h = harness_with("disabled_domains = ['example.org']\n");
	let zone = Zone::with(vec![]);
	run(&h, &zone);
	let h = reconfigured(&h, "");
	run(&h, &zone);
	assert!(holds(&zone.snapshot(), &dkim()));
	assert_eq!(
		of(&zone, "example.org", RecordKind::Mx),
		vec!["10 mail.example.org".to_string()]
	);
	assert_eq!(
		of(&zone, "example.org", RecordKind::Txt),
		vec!["v=spf1 mx -all".to_string()]
	);
}

#[test]
fn a_key_the_operator_wrote_is_not_retired_by_the_role() {
	let (h, zone) = published();
	let theirs = txt("other._domainkey.example.org", "v=DKIM1; k=rsa; p=BBBB");
	zone.records.lock().unwrap().push(theirs.clone());
	let h = reconfigured(&h, "receive_only_domains = ['example.org']\n");
	run(&h, &zone);
	assert!(holds(&zone.snapshot(), &theirs));
}

#[test]
fn the_null_records_of_the_run_do_not_double_the_apex_of_a_disabled_domain() {
	let h =
		harness_with("disabled_domains = ['example.org']\n[dns_publish]\nnull_records = true\n");
	let zone = Zone::with(vec![a("www.example.org")]);
	run(&h, &zone);
	assert_eq!(
		of(&zone, "example.org", RecordKind::Txt),
		vec!["v=spf1 -all".to_string()],
		"one SPF at the apex"
	);
	assert_eq!(
		of(&zone, "example.org", RecordKind::Mx),
		vec!["0 .".to_string()],
		"one MX at the apex"
	);
	let now = zone.snapshot();
	assert!(holds(&now, &txt("www.example.org", "v=spf1 -all")));
	assert!(holds(&now, &rec("www.example.org", RecordKind::Mx, "0 .")));
	let again = read(&h, &zone, &wanted(&h.config));
	assert!(!again.changes(), "{:#?}", again.zones[0].plan.entries);
}

#[test]
fn the_dmarc_policy_is_not_loosened_when_the_domain_goes_back_to_full() {
	// A DMARC record is never replaced by a weaker one: the `reject` the role
	// gave stays until the operator edits it.
	let h = harness_with("receive_only_domains = ['example.org']\n");
	let zone = Zone::with(vec![]);
	run(&h, &zone);
	let h = reconfigured(&h, "");
	run(&h, &zone);
	let dmarc = of(&zone, "_dmarc.example.org", RecordKind::Txt);
	assert!(dmarc[0].contains("p=reject"), "{dmarc:?}");
}
