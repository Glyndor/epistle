//! Which names get the null records: any depth, any record type, the
//! parent of a name, the apex, and what is left alone.

use crate::dns::lockdown::tests::support::*;
use crate::dns::lockdown::{DmarcInputs, Journal, Plan, PlanInput, ServedNames, build_plan};
use crate::dns::provider::{DnsRecord, RecordKind};

/// The plan for `domain` in a zone that is `domain` itself, with
/// `example.org` hosted and `senders` declared as sending.
pub(super) fn plan_for(domain: &str, existing: &[DnsRecord], senders: &[&str]) -> Plan {
	let senders: Vec<String> = senders.iter().map(|s| s.to_string()).collect();
	let served = ServedNames::new(&["example.org".to_string()], "mail.example.org", existing)
		.with_senders(&senders);
	build_plan(&PlanInput {
		zone: domain,
		domain,
		served: &served,
		existing,
		journal: None::<&Journal>,
		dmarc: &DmarcInputs::default(),
		zone_listed: true,
	})
}

fn null_pair() -> Vec<String> {
	vec!["TXT v=spf1 -all".into(), "MX 0 .".into()]
}

#[test]
fn a_name_at_any_depth_gets_both_records() {
	let plan = plan_for("example.org", &[a("a.b.c.d.example.org")], &[]);
	assert_eq!(writes_at(&plan, "a.b.c.d.example.org"), null_pair());
}

#[test]
fn a_name_with_only_text_records_gets_both_records() {
	let plan = plan_for(
		"example.org",
		&[txt("verify.example.org", "site-verification=abc")],
		&[],
	);
	assert_eq!(writes_at(&plan, "verify.example.org"), null_pair());
}

#[test]
fn the_parent_of_a_name_gets_both_records_because_the_wildcard_never_reaches_it() {
	let plan = plan_for("example.org", &[a("x.y.example.org")], &[]);
	assert_eq!(writes_at(&plan, "y.example.org"), null_pair());
	assert_eq!(writes_at(&plan, "x.y.example.org"), null_pair());
}

#[test]
fn the_parent_of_a_wildcard_gets_both_records() {
	let plan = plan_for("example.org", &[txt("*.sub.example.org", "x")], &[]);
	assert_eq!(writes_at(&plan, "sub.example.org"), null_pair());
	assert!(writes_at(&plan, "*.sub.example.org").is_empty());
}

#[test]
fn the_apex_of_a_zone_without_address_records_gets_both_records() {
	let plan = plan_for(
		"other.test",
		&[
			rec("other.test", RecordKind::Ns, "ns1.other.test"),
			rec("other.test", RecordKind::Ns, "ns2.other.test"),
		],
		&[],
	);
	assert_eq!(writes_at(&plan, "other.test"), null_pair());
}

#[test]
fn a_declared_sender_is_left_alone_and_the_names_under_it_are_not() {
	let existing = [a("news.example.org"), a("x.news.example.org")];
	let plan = plan_for("example.org", &existing, &["news.example.org"]);
	assert!(writes_at(&plan, "news.example.org").is_empty());
	assert!(
		skip_reason(&plan, "news.example.org")
			.expect("reported")
			.contains("[dns_publish] senders")
	);
	assert_eq!(writes_at(&plan, "x.news.example.org"), null_pair());
}

#[test]
fn a_sender_is_matched_whatever_its_case() {
	let plan = plan_for(
		"example.org",
		&[a("news.example.org")],
		&["News.Example.ORG"],
	);
	assert!(writes_at(&plan, "news.example.org").is_empty());
}

#[test]
fn a_name_with_its_own_spf_keeps_it_and_still_gets_the_null_mx() {
	let plan = plan_for(
		"example.org",
		&[
			a("app.example.org"),
			txt("app.example.org", "v=spf1 include:x.test -all"),
		],
		&[],
	);
	assert!(writes_at(&plan, "app.example.org").is_empty());
	assert!(
		skip_reason(&plan, "app.example.org")
			.expect("reported")
			.contains("its own SPF record")
	);
}

#[test]
fn a_name_with_its_own_mx_keeps_it_and_gets_no_records() {
	let plan = plan_for(
		"example.org",
		&[
			a("app.example.org"),
			mx("app.example.org", "10 in.example.net"),
		],
		&[],
	);
	assert!(writes_at(&plan, "app.example.org").is_empty());
	assert!(
		skip_reason(&plan, "app.example.org")
			.expect("reported")
			.contains("its own MX record")
	);
}

#[test]
fn a_hosted_domain_stays_alone_even_without_address_records() {
	let plan = plan_for("example.org", &[txt("example.org", "hello")], &[]);
	assert!(writes_at(&plan, "example.org").is_empty());
	assert!(
		plan.skipped.is_empty(),
		"nothing to report: {:?}",
		plan.skipped
	);
}

#[test]
fn a_service_name_without_address_records_is_not_planned() {
	let plan = plan_for(
		"example.org",
		&[txt("_acme-challenge.example.org", "v=DMARC1; p=none")],
		&[],
	);
	assert!(writes_at(&plan, "_acme-challenge.example.org").is_empty());
}

#[test]
fn the_apex_of_a_zone_that_holds_no_record_at_it_gets_both_records() {
	let plan = plan_for("other.test", &[a("www.other.test")], &[]);
	assert_eq!(writes_at(&plan, "other.test"), null_pair());
}
