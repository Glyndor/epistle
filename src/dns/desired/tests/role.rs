//! The role of a domain decides which groups of records the set holds, for
//! every command that reads it.

use super::*;

fn config(extra: &str) -> Config {
	toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = '/var/lib/mail'\ndomains = ['example.org', 'example.net']\n{extra}"
	))
	.expect("config")
}

fn names(desired: &Desired) -> Vec<String> {
	desired
		.records
		.iter()
		.map(|r| format!("{} {}", r.record.name, r.record.kind.as_str()))
		.collect()
}

/// The names of the groups a send-only domain does not carry.
const OMITTED: [&str; 6] = [
	"_mta-sts.example.net TXT",
	"mta-sts.example.net CNAME",
	"_smtp._tls.example.net TXT",
	"_imaps._tcp.example.net SRV",
	"autoconfig.example.net CNAME",
	"autodiscover.example.net CNAME",
];

const SEND_ONLY: &str = "send_only_domains = ['example.net']\n[[listeners]]\nkind = 'imaps'\n[[listeners]]\nkind = 'autoconfig'\n";
const FULL: &str = "[[listeners]]\nkind = 'imaps'\n[[listeners]]\nkind = 'autoconfig'\n";

#[test]
fn a_send_only_domain_has_spf_dmarc_and_mx_and_none_of_the_other_groups() {
	let names = names(&from_config(&config(SEND_ONLY)).expect("set"));
	for needed in [
		"example.net MX",
		"example.net TXT",
		"_dmarc.example.net TXT",
	] {
		assert!(names.contains(&needed.to_string()), "{needed}: {names:?}");
	}
	for omitted in OMITTED {
		assert!(
			!names.contains(&omitted.to_string()),
			"{omitted}: {names:?}"
		);
	}
}

#[test]
fn a_full_domain_keeps_every_group() {
	let names = names(&from_config(&config(FULL)).expect("set"));
	for needed in OMITTED {
		assert!(names.contains(&needed.to_string()), "{needed}: {names:?}");
	}
}

#[test]
fn the_other_domain_is_not_affected_by_a_send_only_one() {
	let names = names(&from_config(&config(SEND_ONLY)).expect("set"));
	for kept in [
		"_mta-sts.example.org TXT",
		"_smtp._tls.example.org TXT",
		"_imaps._tcp.example.org SRV",
		"autoconfig.example.org CNAME",
	] {
		assert!(names.contains(&kept.to_string()), "{kept}: {names:?}");
	}
}

#[test]
fn what_the_role_leaves_out_is_reported_as_skipped() {
	let desired = from_config(&config(SEND_ONLY)).expect("set");
	let skipped: usize = desired.skipped.iter().map(|g| g.records.len()).sum();
	assert_eq!(skipped, OMITTED.len());
}

#[test]
fn changing_the_role_changes_the_set() {
	let full = from_config(&config(FULL)).expect("set");
	let send_only = from_config(&config(SEND_ONLY)).expect("set");
	assert_ne!(names(&full), names(&send_only));
	assert_eq!(names(&full).len() - names(&send_only).len(), OMITTED.len());
}

#[test]
fn the_records_of_one_domain_are_the_ones_the_full_set_holds_for_it() {
	// `domain add` prints this: it must be what `dns-records` lists for the
	// domain and what `verify-dns` checks, not a second computation.
	let config = config(SEND_ONLY);
	let whole = names(&from_config(&config).expect("set"));
	let one = names(&for_domains(&config, &["example.net".to_string()]).expect("set"));
	assert!(!one.is_empty());
	for name in &one {
		assert!(whole.contains(name), "{name}: {whole:?}");
	}
	for name in whole.iter().filter(|n| n.contains("example.net")) {
		assert!(one.contains(name), "{name}: {one:?}");
	}
}

#[test]
fn the_skip_list_and_the_role_both_apply() {
	let names = names(
		&from_config(&config(
			"send_only_domains = ['example.net']\n[dns_publish]\nskip = ['mta-sts']\n",
		))
		.expect("set"),
	);
	assert!(!names.contains(&"_mta-sts.example.org TXT".to_string()));
	assert!(!names.contains(&"_smtp._tls.example.net TXT".to_string()));
	assert!(names.contains(&"_smtp._tls.example.org TXT".to_string()));
}

fn dmarc(desired: &Desired, domain: &str) -> String {
	desired
		.records
		.iter()
		.find(|r| r.record.name == format!("_dmarc.{domain}"))
		.map(|r| r.record.value.clone())
		.expect("a DMARC record")
}

#[test]
fn a_send_only_domain_has_no_report_address_that_nobody_reads() {
	// `domain add` does not create `postmaster@` on a hosted domain, so a
	// `rua` pointing there would only bounce the reports.
	let desired = from_config(&config(SEND_ONLY)).expect("set");
	assert_eq!(
		dmarc(&desired, "example.net"),
		"v=DMARC1; p=quarantine; adkim=s; aspf=s"
	);
	assert_eq!(
		dmarc(&desired, "example.org"),
		"v=DMARC1; p=quarantine; rua=mailto:postmaster@example.org; adkim=s; aspf=s"
	);
}

fn value(desired: &Desired, name: &str, kind: crate::dns::provider::RecordKind) -> Vec<String> {
	desired
		.records
		.iter()
		.filter(|r| r.record.name == name && r.record.kind == kind)
		.map(|r| r.record.value.clone())
		.collect()
}

const RECEIVE_ONLY: &str =
	"receive_only_domains = ['example.net']\n[[listeners]]\nkind = 'imaps'\n";
const DISABLED: &str = "disabled_domains = ['example.net']\n[[listeners]]\nkind = 'imaps'\n";

#[test]
fn a_receive_only_domain_has_the_null_spf_a_reject_policy_and_no_key() {
	use crate::dns::provider::RecordKind::{Mx, Txt};
	let desired = from_config(&config(RECEIVE_ONLY)).expect("set");
	assert_eq!(value(&desired, "example.net", Txt), ["v=spf1 -all"]);
	assert_eq!(value(&desired, "example.net", Mx), ["10 mail.example.org"]);
	assert_eq!(
		dmarc(&desired, "example.net"),
		"v=DMARC1; p=reject; rua=mailto:postmaster@example.net; adkim=s; aspf=s"
	);
	// The domain that sends keeps its SPF and its policy.
	assert_eq!(value(&desired, "example.org", Txt), ["v=spf1 mx -all"]);
	assert!(dmarc(&desired, "example.org").contains("p=quarantine"));
	let names = names(&desired);
	assert!(
		names.contains(&"_mta-sts.example.net TXT".to_string()),
		"{names:?}"
	);
	assert!(
		names.contains(&"_imaps._tcp.example.net SRV".to_string()),
		"{names:?}"
	);
}

#[test]
fn a_disabled_domain_has_the_null_spf_the_null_mx_and_none_of_the_groups() {
	use crate::dns::provider::RecordKind::{Mx, Txt};
	let desired = from_config(&config(DISABLED)).expect("set");
	assert_eq!(value(&desired, "example.net", Txt), ["v=spf1 -all"]);
	assert_eq!(value(&desired, "example.net", Mx), ["0 ."]);
	assert_eq!(
		dmarc(&desired, "example.net"),
		"v=DMARC1; p=reject; adkim=s; aspf=s"
	);
	let names = names(&desired);
	for omitted in OMITTED {
		assert!(
			!names.contains(&omitted.to_string()),
			"{omitted}: {names:?}"
		);
	}
	assert_eq!(value(&desired, "example.org", Mx), ["10 mail.example.org"]);
}

#[test]
fn a_domain_that_sends_nothing_publishes_no_key_however_it_is_configured() {
	use crate::dns::provider::RecordKind::Txt;
	use crate::dns::records::{DomainDkim, ServiceRecords, build_records_for_roles};
	let pairs = [("sel".to_string(), "v=DKIM1; k=ed25519; p=AAAA".to_string())];
	for (extra, signs) in [
		("", true),
		("send_only_domains = ['example.net']", true),
		("receive_only_domains = ['example.net']", false),
		("disabled_domains = ['example.net']", false),
	] {
		let config = config(extra);
		let records = build_records_for_roles(
			&config.domains,
			&config.hostname,
			(&pairs, &DomainDkim::new()),
			(None, "1", ServiceRecords::default()),
			(None, None, None),
			&config.roles(),
		);
		let found = records
			.iter()
			.any(|r| r.record.name == "sel._domainkey.example.net" && r.record.kind == Txt);
		assert_eq!(found, signs, "{extra:?}");
		assert!(
			records
				.iter()
				.any(|r| r.record.name == "sel._domainkey.example.org"),
			"the other domain keeps its key"
		);
	}
}
