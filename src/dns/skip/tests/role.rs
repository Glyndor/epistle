//! The role of a hosted domain is one more reason a group is skipped, for
//! the records of that domain only.

use super::super::*;
use crate::dns::provider::{DnsRecord, RecordKind};

fn record(name: &str, kind: RecordKind) -> DnsRecord {
	DnsRecord::new(name, kind, "x", 3600)
}

fn set(hosted: &[&str], send_only: &[&str]) -> SkipSet {
	let own = |names: &[&str]| names.iter().map(|n| n.to_string()).collect::<Vec<_>>();
	SkipSet::default().with_roles(Roles::new(&own(hosted), &own(send_only)))
}

/// Every record a full domain carries beyond the core ones.
fn extras(domain: &str) -> Vec<DnsRecord> {
	vec![
		record(&format!("_mta-sts.{domain}"), RecordKind::Txt),
		record(&format!("mta-sts.{domain}"), RecordKind::Cname),
		record(&format!("_smtp._tls.{domain}"), RecordKind::Txt),
		record(&format!("_imaps._tcp.{domain}"), RecordKind::Srv),
		record(&format!("autoconfig.{domain}"), RecordKind::Cname),
		record(&format!("autodiscover.{domain}"), RecordKind::Cname),
	]
}

/// What a domain of every role keeps: SPF, DMARC, DKIM and MX.
fn core(domain: &str) -> Vec<DnsRecord> {
	vec![
		record(domain, RecordKind::Txt),
		record(&format!("_dmarc.{domain}"), RecordKind::Txt),
		record(&format!("sel._domainkey.{domain}"), RecordKind::Txt),
		record(domain, RecordKind::Mx),
	]
}

#[test]
fn a_send_only_domain_skips_every_extra_group() {
	let skip = set(&["example.org"], &["example.org"]);
	for extra in extras("example.org") {
		assert!(skip.group_of(&extra).is_some(), "{extra:?}");
	}
}

#[test]
fn a_send_only_domain_keeps_spf_dkim_dmarc_and_mx() {
	let skip = set(&["example.org"], &["example.org"]);
	for kept in core("example.org") {
		assert_eq!(skip.group_of(&kept), None, "{kept:?}");
	}
}

#[test]
fn a_full_domain_skips_nothing() {
	let skip = set(&["example.org"], &[]);
	for record in extras("example.org").into_iter().chain(core("example.org")) {
		assert_eq!(skip.group_of(&record), None, "{record:?}");
	}
}

#[test]
fn the_role_of_one_domain_does_not_reach_another() {
	let skip = set(&["example.org", "example.net"], &["example.net"]);
	for extra in extras("example.org") {
		assert_eq!(skip.group_of(&extra), None, "{extra:?}");
	}
	assert!(skip.group_of(&extras("example.net")[0]).is_some());
}

#[test]
fn a_subdomain_that_is_hosted_has_its_own_role() {
	// `_mta-sts.sub.example.org` ends in `.example.org`, but the longest
	// hosted domain it is in is `sub.example.org`.
	let skip = set(&["example.org", "sub.example.org"], &["example.org"]);
	assert_eq!(skip.group_of(&extras("sub.example.org")[0]), None);
	assert!(skip.group_of(&extras("example.org")[0]).is_some());
}

#[test]
fn a_name_that_only_ends_alike_is_not_in_the_domain() {
	let skip = set(&["example.org"], &["example.org"]);
	assert_eq!(skip.group_of(&extras("notexample.org")[0]), None);
}

#[test]
fn the_skip_list_still_applies_to_a_full_domain() {
	let skip =
		SkipSet::new([SkipGroup::MtaSts]).with_roles(Roles::new(&["example.org".to_string()], &[]));
	assert_eq!(
		skip.group_of(&record("_mta-sts.example.org", RecordKind::Txt)),
		Some(SkipGroup::MtaSts)
	);
	assert_eq!(
		skip.group_of(&record("_smtp._tls.example.org", RecordKind::Txt)),
		None
	);
}

#[test]
fn the_check_of_a_send_only_domain_is_marked_skipped() {
	let checks = vec![crate::dns::Check::missing(
		"MTA-STS",
		"_mta-sts.example.org",
		"no record",
	)];
	let marked = split_checks(checks.clone(), &set(&["example.org"], &["example.org"]));
	assert_eq!(marked[0].status, crate::dns::Status::Skipped);
	let kept = split_checks(checks, &set(&["example.org"], &[]));
	assert_eq!(kept[0].status, crate::dns::Status::Missing);
}

fn roles_of(receive_only: &[&str], disabled: &[&str]) -> Roles {
	let own = |names: &[&str]| names.iter().map(|n| n.to_string()).collect::<Vec<_>>();
	Roles::new(
		&own(&["example.org", "example.net", "example.com"]),
		&own(&["example.net"]),
	)
	.with_others(&own(receive_only), &own(disabled))
}

#[test]
fn every_role_has_its_name() {
	let roles = roles_of(&["example.org"], &["example.com"]);
	assert_eq!(roles.of_name("example.net"), DomainRole::SendOnly);
	assert_eq!(roles.of_name("example.org"), DomainRole::ReceiveOnly);
	assert_eq!(roles.of_name("example.com"), DomainRole::Disabled);
	assert_eq!(roles.of_name("example.org").name(), "receive-only");
	assert_eq!(roles.of_name("example.com").name(), "disabled");
}

#[test]
fn a_switched_off_domain_is_disabled_whatever_else_lists_it() {
	let roles = roles_of(&["example.org"], &["example.org", "example.net"]);
	assert_eq!(roles.of_name("example.org"), DomainRole::Disabled);
	assert_eq!(roles.of_name("example.net"), DomainRole::Disabled);
}

#[test]
fn what_each_role_sends_and_receives() {
	assert!(DomainRole::Full.sends() && DomainRole::Full.receives());
	assert!(DomainRole::SendOnly.sends() && !DomainRole::SendOnly.receives());
	assert!(!DomainRole::ReceiveOnly.sends() && DomainRole::ReceiveOnly.receives());
	assert!(!DomainRole::Disabled.sends() && !DomainRole::Disabled.receives());
}

#[test]
fn a_domain_that_sends_nothing_has_the_null_spf_and_a_reject_policy() {
	assert_eq!(DomainRole::Full.spf(), "v=spf1 mx -all");
	assert_eq!(DomainRole::SendOnly.spf(), "v=spf1 mx -all");
	assert_eq!(DomainRole::ReceiveOnly.spf(), "v=spf1 -all");
	assert_eq!(DomainRole::Disabled.spf(), "v=spf1 -all");
	assert_eq!(DomainRole::Full.dmarc_policy(), "quarantine");
	assert_eq!(DomainRole::SendOnly.dmarc_policy(), "quarantine");
	assert_eq!(DomainRole::ReceiveOnly.dmarc_policy(), "reject");
	assert_eq!(DomainRole::Disabled.dmarc_policy(), "reject");
}

#[test]
fn only_a_switched_off_domain_has_the_null_mx() {
	assert_eq!(
		DomainRole::Full.mx("mail.example.org"),
		"10 mail.example.org"
	);
	assert_eq!(
		DomainRole::SendOnly.mx("mail.example.org"),
		"10 mail.example.org"
	);
	assert_eq!(
		DomainRole::ReceiveOnly.mx("mail.example.org"),
		"10 mail.example.org"
	);
	assert_eq!(DomainRole::Disabled.mx("mail.example.org"), "0 .");
}

#[test]
fn a_receive_only_domain_keeps_every_group_and_a_disabled_one_skips_the_receiving_ones() {
	let roles = roles_of(&["example.org"], &["example.com"]);
	let skip = SkipSet::default().with_roles(roles);
	for extra in extras("example.org") {
		assert_eq!(skip.group_of(&extra), None, "{extra:?}");
	}
	for extra in extras("example.com") {
		assert!(skip.group_of(&extra).is_some(), "{extra:?}");
	}
}
