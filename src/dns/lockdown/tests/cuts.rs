//! Tests for the delegations the lockdown leaves alone: a subdomain whose
//! NS records hand it to other nameservers, and everything under it. A
//! record written there is occluded or refused, and a wrong guess about
//! where a delegation starts either writes under someone else's zone or
//! leaves a name unprotected.

use std::time::{Duration, Instant};

use super::support::*;
use super::*;
use crate::dns::names::shortened;

fn ns(name: &str, target: &str) -> DnsRecord {
	rec(name, RecordKind::Ns, target)
}

/// The plan for `domain` in `zone` against `existing`.
fn plan_in(zone: &str, domain: &str, existing: &[DnsRecord]) -> Plan {
	let served = ServedNames::new(&[domain.to_string()], &format!("mail.{domain}"), existing);
	build_plan(&PlanInput {
		zone,
		domain,
		served: &served,
		existing,
		journal: None,
		dmarc: &DmarcInputs::default(),
		zone_listed: true,
	})
}

fn skipped(plan: &Plan) -> Vec<(String, String)> {
	plan.skipped
		.iter()
		.map(|s| (s.name.clone(), s.reason.clone()))
		.collect()
}

fn delegated(name: &str) -> (String, String) {
	(
		name.to_string(),
		format!("{name} is delegated to other nameservers; left as is"),
	)
}

#[test]
fn a_delegated_subdomain_and_everything_under_it_is_left_alone() {
	let plan = plan(&[
		ns("sub.example.org", "ns1.delegated.example."),
		ns("sub.example.org", "ns2.delegated.example."),
		a("sub.example.org"),
		a("host.sub.example.org"),
		a("deep.host.sub.example.org"),
		a("www.example.org"),
	]);
	for name in [
		"sub.example.org",
		"host.sub.example.org",
		"deep.host.sub.example.org",
	] {
		assert!(writes_at(&plan, name).is_empty(), "{name}: {plan:?}");
	}
	assert_eq!(
		writes_at(&plan, "www.example.org"),
		vec!["TXT v=spf1 -all", "MX 0 ."],
		"a name outside the delegation is still locked down"
	);
	assert_eq!(skipped(&plan), vec![delegated("sub.example.org")]);
}

#[test]
fn a_delegation_with_no_address_is_still_reported() {
	let plan = plan(&[ns("sub.example.org", "ns1.delegated.example.")]);
	assert_eq!(skipped(&plan), vec![delegated("sub.example.org")]);
	assert!(plan.entries.iter().all(|e| !e.record.name.contains("sub.")));
}

#[test]
fn two_delegations_one_inside_the_other_are_both_reported() {
	let plan = plan(&[
		ns("sub.example.org", "ns1.delegated.example."),
		ns("a.sub.example.org", "ns1.other.example."),
		a("x.a.sub.example.org"),
	]);
	assert!(
		writes_at(&plan, "x.a.sub.example.org").is_empty(),
		"{plan:?}"
	);
	assert_eq!(
		skipped(&plan),
		vec![delegated("a.sub.example.org"), delegated("sub.example.org")]
	);
}

#[test]
fn the_ns_records_of_the_zone_apex_are_not_a_delegation() {
	let plan = plan(&[
		a("example.org"),
		ns("example.org", "ns1.example.net."),
		ns("example.org", "ns2.example.net."),
		a("www.example.org"),
	]);
	assert_eq!(
		writes_at(&plan, "www.example.org"),
		vec!["TXT v=spf1 -all", "MX 0 ."]
	);
	assert_eq!(
		skipped(&plan),
		vec![(
			"example.org".to_string(),
			"epistle serves example.org (a mail domain epistle hosts); left as is".to_string()
		)]
	);
}

#[test]
fn a_delegation_is_found_whatever_its_spelling() {
	let plan = plan(&[
		ns("SUB.Example.Org.", "ns1.delegated.example."),
		a("Host.Sub.example.org"),
	]);
	assert!(
		writes_at(&plan, "host.sub.example.org").is_empty(),
		"{plan:?}"
	);
	assert_eq!(skipped(&plan), vec![delegated("sub.example.org")]);
}

#[test]
fn an_ns_outside_the_zone_changes_nothing() {
	let plan = plan(&[
		ns("sub.other.example", "ns1.delegated.example."),
		ns("example.org.evil.net", "ns1.delegated.example."),
		a("www.example.org"),
	]);
	assert_eq!(
		writes_at(&plan, "www.example.org"),
		vec!["TXT v=spf1 -all", "MX 0 ."]
	);
	assert!(plan.skipped.is_empty(), "{plan:?}");
}

#[test]
fn a_domain_inside_a_delegation_gets_no_record_at_all() {
	let plan = plan_in(
		"example.org",
		"eu.example.org",
		&[
			ns("eu.example.org", "ns1.delegated.example."),
			a("www.eu.example.org"),
			txt("_dmarc.eu.example.org", "v=DMARC1; p=none"),
		],
	);
	assert!(plan.entries.is_empty(), "{plan:?}");
	let reason = "eu.example.org is delegated to other nameservers; left as is";
	assert_eq!(
		plan.dmarc.action,
		DmarcAction::LeftAlone {
			reason: reason.to_string()
		}
	);
	assert_eq!(
		plan.wildcard,
		WildcardDecision::Skipped {
			reason: reason.to_string()
		}
	);
	assert_eq!(skipped(&plan), vec![delegated("eu.example.org")]);
}

#[test]
fn the_ns_of_a_domain_that_is_its_own_zone_is_not_a_delegation() {
	let plan = plan_in(
		"eu.example.org",
		"eu.example.org",
		&[
			ns("eu.example.org", "ns1.example.net."),
			a("www.eu.example.org"),
			txt("_dmarc.eu.example.org", "v=DMARC1; p=none"),
		],
	);
	assert_eq!(
		writes_at(&plan, "www.eu.example.org"),
		vec!["TXT v=spf1 -all", "MX 0 ."]
	);
	assert!(
		matches!(plan.dmarc.action, DmarcAction::Publish),
		"{:?}",
		plan.dmarc
	);
}

#[test]
fn a_delegated_dmarc_name_is_left_alone() {
	let plan = plan(&[
		ns("_dmarc.example.org", "ns1.delegated.example."),
		txt("_dmarc.example.org", "v=DMARC1; p=none"),
	]);
	assert_eq!(
		plan.dmarc.action,
		DmarcAction::LeftAlone {
			reason: "_dmarc.example.org is delegated to other nameservers; left as is".to_string()
		}
	);
	assert!(
		writes_at(&plan, "_dmarc.example.org").is_empty(),
		"{plan:?}"
	);
}

#[test]
fn a_name_that_cannot_be_a_dns_name_is_reported_cut_down() {
	let long_label = format!("{}.example.org", "a".repeat(64));
	let many_labels = format!("{}.example.org", vec!["a"; 140].join("."));
	let huge = format!("{}.example.org", "a".repeat(10 * 1024 * 1024));
	let plan = plan(&[
		a(&long_label),
		a(&many_labels),
		a(&huge),
		a("www.example.org"),
	]);
	assert_eq!(
		writes_at(&plan, "www.example.org"),
		vec!["TXT v=spf1 -all", "MX 0 ."]
	);
	let reasons = skipped(&plan);
	assert_eq!(reasons.len(), 3, "{reasons:?}");
	for (name, reason) in &reasons {
		assert!(
			name.len() <= 256,
			"a skipped name is cut: {} bytes",
			name.len()
		);
		assert_eq!(
			reason,
			&format!(
				"{name} is not a valid DNS name (ASCII letters, digits, hyphens and underscores, at most 253 characters and 63 per label); left as is"
			)
		);
	}
	assert_eq!(shortened("example.org"), "example.org");
	assert_eq!(
		shortened(&"é".repeat(300)).len(),
		252 + 3,
		"cut on a character"
	);
}

/// Forty thousand names, a thousand delegations and names a hundred
/// labels deep: the plan is built in one pass over the zone. A name-by-name
/// search of the zone would take minutes here.
#[test]
fn a_huge_zone_with_many_delegations_is_planned_in_one_pass() {
	let mut existing = Vec::new();
	for i in 0..1_000 {
		existing.push(ns(&format!("d{i}.example.org"), "ns1.delegated.example."));
		for j in 0..20 {
			existing.push(a(&format!("h{j}.d{i}.example.org")));
		}
	}
	existing.push(a(&format!("{}d0.example.org", "x.".repeat(100))));
	for i in 0..20_000 {
		existing.push(a(&format!("f{i}.example.org")));
	}
	let started = Instant::now();
	let plan = plan(&existing);
	let took = started.elapsed();
	let free = plan
		.entries
		.iter()
		.filter(|e| e.record.name.starts_with('f'))
		.count();
	assert_eq!(free, 2 * 20_000, "two records for each of the free names");
	let under_a_cut = plan
		.entries
		.iter()
		.filter(|e| e.record.name.starts_with('h') || e.record.name.starts_with("x."))
		.count();
	assert_eq!(under_a_cut, 0, "nothing is planned under a delegation");
	assert_eq!(plan.skipped.len(), 1_000, "one line for each delegation");
	assert!(
		took < Duration::from_secs(10),
		"planning {} records took {took:?}",
		existing.len()
	);
}

/// Nothing is followed: a CNAME that points back at itself through another
/// name, and an NS whose target sits under the very name it delegates,
/// are two records each, read once.
#[test]
fn loops_in_the_zone_are_not_followed() {
	let plan = plan(&[
		rec("a.example.org", RecordKind::Cname, "b.example.org."),
		rec("b.example.org", RecordKind::Cname, "a.example.org."),
		ns("loop.example.org", "ns1.loop.example.org."),
		a("ns1.loop.example.org"),
		ns("self.example.org", "self.example.org."),
	]);
	assert_eq!(
		skipped(&plan),
		vec![
			delegated("loop.example.org"),
			delegated("self.example.org"),
			(
				"a.example.org".to_string(),
				"a.example.org is a CNAME, and no other record may sit next to a CNAME (RFC 1034 section 3.6.2); a null SPF and null MX belong at the name it points to; left as is".to_string()
			),
			(
				"b.example.org".to_string(),
				"b.example.org is a CNAME, and no other record may sit next to a CNAME (RFC 1034 section 3.6.2); a null SPF and null MX belong at the name it points to; left as is".to_string()
			),
		]
	);
}

/// A record is written back under the name that was read, so a name with an
/// escape sequence, a NUL or a space is reported and never planned: a
/// provider that lists one (or an account that created one) cannot make the
/// lockdown write to it.
#[test]
fn a_name_outside_letters_digits_hyphens_and_underscores_is_never_written() {
	let plan = plan(&[
		a("ev\u{1b}[2Jil.example.org"),
		a("nul\0.example.org"),
		a("sp ace.example.org"),
		a("b\u{fc}cher.example.org"),
		a("under_score.example.org"),
		a("www.example.org"),
	]);
	let mut written: Vec<&str> = plan
		.entries
		.iter()
		.map(|e| e.record.name.as_str())
		.filter(|n| n.contains("www") || n.contains("under") || n.contains("xn--"))
		.collect();
	written.sort_unstable();
	written.dedup();
	assert_eq!(
		written,
		vec![
			"under_score.example.org",
			"www.example.org",
			"xn--bcher-kva.example.org"
		]
	);
	assert!(
		plan.entries
			.iter()
			.all(|e| !e.record.name.contains(['\u{1b}', '\0', ' '])),
		"{plan:?}"
	);
	let reason = "is not a valid DNS name (ASCII letters, digits, hyphens and underscores, at most 253 characters and 63 per label); left as is";
	let names: Vec<String> = skipped(&plan)
		.into_iter()
		.filter(|(_, r)| r.ends_with(reason))
		.map(|(n, _)| n)
		.collect();
	assert_eq!(
		names,
		vec![
			"ev\u{1b}[2jil.example.org".to_string(),
			"nul\0.example.org".to_string(),
			"sp ace.example.org".to_string()
		]
	);
}

/// A wildcard under a delegation belongs to the other nameservers: it never
/// answers for a name of this zone, so it is no reason to skip the
/// wildcard null SPF of the domain.
#[test]
fn a_wildcard_hidden_by_a_delegation_does_not_block_the_null_wildcard() {
	let plan = plan(&[
		ns("sub.example.org", "ns1.delegated.example."),
		txt("*.sub.example.org", "v=spf1 +all"),
		a("www.example.org"),
	]);
	assert!(
		matches!(plan.wildcard, WildcardDecision::Added { .. }),
		"{:?}",
		plan.wildcard
	);
	assert_eq!(writes_at(&plan, "*.example.org"), vec!["TXT v=spf1 -all"]);
}

/// An NS at a wildcard hands nothing over (RFC 4592): it is no delegation,
/// and no name is left alone because of it.
#[test]
fn an_ns_at_a_wildcard_is_not_a_delegation() {
	let existing = [
		ns("*.example.org", "ns1.delegated.example."),
		a("www.example.org"),
	];
	let plan = plan(&existing);
	assert_eq!(
		writes_at(&plan, "www.example.org"),
		vec!["TXT v=spf1 -all", "MX 0 ."]
	);
	assert!(
		skipped(&plan).iter().all(|(_, r)| !r.contains("delegated")),
		"{:?}",
		skipped(&plan)
	);
	let cuts = Cuts::new("example.org", &existing);
	assert_eq!(cuts.above("host.example.org"), None);
	assert_eq!(cuts.above("*.example.org"), None);
}

/// A name delegated after the lockdown wrote a record there is the other
/// nameservers' now: `--undo` reports the record and does not touch it.
#[tokio::test]
async fn undo_leaves_a_record_in_a_name_delegated_since() {
	let ours = txt("sub.example.org", NULL_SPF);
	let zone = Zone::with(vec![
		ns("sub.example.org", "ns1.delegated.example."),
		ours.clone(),
		txt("www.example.org", NULL_SPF),
	]);
	let journal = Journal {
		domain: "example.org".into(),
		entries: vec![
			JournalEntry {
				record: txt("www.example.org", NULL_SPF),
				replaced: None,
			},
			JournalEntry {
				record: ours.clone(),
				replaced: None,
			},
		],
	};
	let report = undo_journal(&zone, "example.org", &journal, false)
		.await
		.expect("undo");
	assert_eq!(report.deleted, vec![txt("www.example.org", NULL_SPF)]);
	assert_eq!(
		report.changed,
		vec![UndoChanged {
			record: ours.clone(),
			now: vec!["sub.example.org is delegated to other nameservers".to_string()],
		}]
	);
	assert!(zone.snapshot().contains(&ours));
	assert_eq!(*zone.writes.lock().unwrap(), 1);
}

#[allow(unused_imports)]
use super::super::dmarc;
