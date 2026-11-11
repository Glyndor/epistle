//! A delegated subdomain is left intact: nothing is planned at it or under
//! it, and publishing the plan against a zone in memory changes none of its
//! records.

use super::base::plan_for;
use crate::dns::lockdown::tests::support::*;
use crate::dns::lockdown::{DmarcInputs, PlanInput, ServedNames, build_plan, publish_plan};
use crate::dns::provider::{DnsRecord, RecordKind};

fn under(records: &[DnsRecord], cut: &str) -> Vec<String> {
	let mut lines: Vec<String> = records
		.iter()
		.filter(|r| r.name == cut || r.name.ends_with(&format!(".{cut}")))
		.map(|r| format!("{} {} {}", r.name, r.kind.as_str(), r.value))
		.collect();
	lines.sort();
	lines
}

#[tokio::test]
async fn publishing_leaves_a_delegated_subdomain_intact_and_covers_the_rest() {
	let zone = Zone::with(vec![
		a("www.example.org"),
		a("deep.er.www.example.org"),
		rec("sub.example.org", RecordKind::Ns, "ns.elsewhere.test"),
		a("host.sub.example.org"),
		txt("txt-only.sub.example.org", "kept"),
		a("x.y.sub.example.org"),
	]);
	let before = under(&zone.snapshot(), "sub.example.org");
	let existing = zone.snapshot();
	let served = ServedNames::new(&["example.org".to_string()], "mail.example.org", &existing);
	let plan = build_plan(&PlanInput {
		zone: "example.org",
		domain: "example.org",
		served: &served,
		existing: &existing,
		journal: None,
		dmarc: &DmarcInputs::default(),
		zone_listed: true,
	});
	publish_plan(&zone, "example.org", &plan, None, &mut |_| Ok(()))
		.await
		.expect("publish");
	let after = zone.snapshot();
	assert_eq!(
		under(&after, "sub.example.org"),
		before,
		"the delegation is untouched"
	);
	for name in [
		"www.example.org",
		"er.www.example.org",
		"deep.er.www.example.org",
	] {
		assert!(
			after
				.iter()
				.any(|r| r.name == name && r.kind == RecordKind::Mx && r.value == "0 ."),
			"{name} gets a null MX"
		);
		assert!(
			after
				.iter()
				.any(|r| r.name == name && r.kind == RecordKind::Txt && r.value == "v=spf1 -all"),
			"{name} gets a null SPF"
		);
	}
}

#[test]
fn a_name_under_a_cut_is_not_planned_and_the_cut_is_reported() {
	let plan = plan_for(
		"example.org",
		&[
			rec("sub.example.org", RecordKind::Ns, "ns.elsewhere.test"),
			txt("only.sub.example.org", "x"),
		],
		&[],
	);
	assert!(writes_at(&plan, "sub.example.org").is_empty());
	assert!(writes_at(&plan, "only.sub.example.org").is_empty());
	assert!(skip_reason(&plan, "sub.example.org").is_some());
}
