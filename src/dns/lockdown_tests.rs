//! Tests for which names the lockdown plan touches and which it leaves
//! alone, with the exact reasons the operator reads, and the wildcard.

use super::tests_support::*;
use super::*;

#[test]
fn a_name_with_only_an_address_gets_a_null_spf_and_a_null_mx() {
	let plan = plan(&[a("www.example.org")]);
	assert_eq!(
		writes_at(&plan, "www.example.org"),
		vec!["TXT v=spf1 -all", "MX 0 ."]
	);
	let reasons: Vec<&str> = plan
		.entries
		.iter()
		.filter(|e| e.record.name == "www.example.org")
		.map(|e| e.reason.as_str())
		.collect();
	assert_eq!(
		reasons,
		vec![
			"www.example.org has an address record and no SPF; v=spf1 -all says it sends no mail",
			"www.example.org has an address record and no MX; MX 0 . (RFC 7505) says it accepts no mail",
		]
	);
}

#[test]
fn a_name_with_its_own_mx_gets_nothing_at_all() {
	let plan = plan(&[
		a("lists.example.org"),
		mx("lists.example.org", "10 mx.example.net"),
	]);
	assert!(writes_at(&plan, "lists.example.org").is_empty(), "{plan:?}");
	assert_eq!(
		skip_reason(&plan, "lists.example.org").as_deref(),
		Some("lists.example.org has its own MX record; left as is")
	);
}

#[test]
fn a_name_with_its_own_spf_gets_no_null_mx() {
	// A null MX on a name that sends mail makes receivers refuse its mail
	// (RFC 7505 section 4.2): the whole name is left alone.
	let plan = plan(&[
		a("news.example.org"),
		txt("news.example.org", "v=spf1 include:mailer.example.net -all"),
	]);
	assert!(writes_at(&plan, "news.example.org").is_empty(), "{plan:?}");
	assert_eq!(
		skip_reason(&plan, "news.example.org").as_deref(),
		Some("news.example.org has its own SPF record; left as is")
	);
}

#[test]
fn a_name_with_its_own_spf_and_mx_says_both() {
	let plan = plan(&[
		a("shop.example.org"),
		txt("shop.example.org", "v=spf1 a -all"),
		mx("shop.example.org", "10 shop.example.org"),
	]);
	assert_eq!(
		skip_reason(&plan, "shop.example.org").as_deref(),
		Some("shop.example.org has its own SPF and MX records; left as is")
	);
}

#[test]
fn a_cname_gets_no_record_next_to_it() {
	let plan = plan(&[rec(
		"blog.example.org",
		RecordKind::Cname,
		"blogs.example.net",
	)]);
	assert!(writes_at(&plan, "blog.example.org").is_empty(), "{plan:?}");
	assert_eq!(
		skip_reason(&plan, "blog.example.org").as_deref(),
		Some(
			"blog.example.org is a CNAME, and no other record may sit next to a CNAME (RFC 1034 section 3.6.2); a null SPF and null MX belong at the name it points to; left as is"
		)
	);
}

#[test]
fn a_dkim_selector_delegated_by_cname_is_a_service_name() {
	let name = "s1._domainkey.example.org";
	let plan = plan(&[rec(name, RecordKind::Cname, "s1.dkim.example.net")]);
	assert!(writes_at(&plan, name).is_empty(), "{plan:?}");
	assert_eq!(
		skip_reason(&plan, name).as_deref(),
		Some(
			"s1._domainkey.example.org is a service name (a label starts with an underscore), not a host that sends mail; left as is"
		)
	);
}

#[test]
fn every_name_epistle_serves_is_reported_with_its_role() {
	let existing = vec![
		a("example.org"),
		a("mail.example.org"),
		rec(
			"autoconfig.example.org",
			RecordKind::Cname,
			"mail.example.org",
		),
		rec(
			"autodiscover.example.org",
			RecordKind::Cname,
			"mail.example.org",
		),
		a("mta-sts.example.org"),
		mx("example.org", "10 mx1.example.org."),
		a("mx1.example.org"),
		rec("_dmarc.example.org", RecordKind::Cname, "dmarc.example.net"),
	];
	let plan = plan(&existing);
	let expected = [
		("example.org", "a mail domain epistle hosts"),
		("mail.example.org", "the mail hostname"),
		(
			"autoconfig.example.org",
			"mail client autoconfiguration of example.org",
		),
		(
			"autodiscover.example.org",
			"mail client autodiscovery of example.org",
		),
		(
			"mta-sts.example.org",
			"the MTA-STS policy host of example.org",
		),
		("mx1.example.org", "an MX target of example.org"),
		("_dmarc.example.org", "the DMARC record of example.org"),
	];
	for (name, role) in expected {
		assert!(
			writes_at(&plan, name).is_empty(),
			"{name} got records: {plan:?}"
		);
		assert_eq!(
			skip_reason(&plan, name),
			Some(format!("epistle serves {name} ({role}); left as is")),
			"{name}"
		);
	}
}

#[test]
fn a_mail_server_of_another_name_keeps_its_own_spf_freedom() {
	// relay sends bounces as itself (HELO identity): a null SPF there
	// would make receivers refuse them.
	let plan = plan(&[
		a("lists.example.org"),
		mx("lists.example.org", "10 relay.example.org."),
		a("relay.example.org"),
	]);
	assert!(writes_at(&plan, "relay.example.org").is_empty(), "{plan:?}");
	assert_eq!(
		skip_reason(&plan, "relay.example.org").as_deref(),
		Some(
			"relay.example.org is an MX target of lists.example.org, so it is a mail server and may send as itself; left as is"
		)
	);
}

#[test]
fn a_hosted_subdomain_is_served_like_the_apex() {
	let existing = vec![a("lists.example.org"), a("autoconfig.lists.example.org")];
	let served = ServedNames::new(
		&["example.org".into(), "lists.example.org".into()],
		"mail.example.org",
		&existing,
	);
	let plan = build_plan(&PlanInput {
		domain: "example.org",
		served: &served,
		existing: &existing,
		journal: None,
		dmarc: &DmarcInputs::default(),
		zone_listed: true,
	});
	assert!(writes_at(&plan, "lists.example.org").is_empty(), "{plan:?}");
	assert!(
		writes_at(&plan, "autoconfig.lists.example.org").is_empty(),
		"{plan:?}"
	);
}

#[test]
fn provider_spellings_of_a_name_compare_as_one_name() {
	assert_eq!(
		canonical_name(" Bücher.Example.ORG. "),
		"xn--bcher-kva.example.org"
	);
	assert_eq!(canonical_name("*.Example.org."), "*.example.org");
	// The hostname listed with capitals and the root dot is still served.
	let plan = plan(&[a("MAIL.Example.org."), a("Bücher.example.org")]);
	assert_eq!(
		skip_reason(&plan, "mail.example.org").as_deref(),
		Some("epistle serves mail.example.org (the mail hostname); left as is")
	);
	assert_eq!(
		writes_at(&plan, "xn--bcher-kva.example.org"),
		vec!["TXT v=spf1 -all", "MX 0 ."]
	);
}

#[test]
fn names_outside_the_domain_are_not_planned() {
	let served = served(&[]);
	let existing = vec![a("www.example.org"), a("www.shop.example.org")];
	let plan = build_plan(&PlanInput {
		domain: "shop.example.org",
		served: &served,
		existing: &existing,
		journal: None,
		dmarc: &DmarcInputs::default(),
		zone_listed: true,
	});
	assert!(writes_at(&plan, "www.example.org").is_empty());
	assert!(skip_reason(&plan, "www.example.org").is_none());
	assert_eq!(writes_at(&plan, "www.shop.example.org").len(), 2);
	assert_eq!(
		plan.entries.last().unwrap().record.name,
		"*.shop.example.org"
	);
}

#[test]
fn the_wildcard_is_added_when_the_zone_has_none() {
	let plan = plan(&[]);
	assert_eq!(writes_at(&plan, "*.example.org"), vec!["TXT v=spf1 -all"]);
	assert_eq!(
		plan.wildcard,
		WildcardDecision::Added {
			reason: "the zone has no wildcard; *.example.org v=spf1 -all covers names that do not exist (a wildcard never applies to a name that has records of its own)".into()
		}
	);
}

#[test]
fn any_wildcard_of_the_zone_keeps_the_null_wildcard_out() {
	let plan = plan(&[
		a("*.example.org"),
		rec("*.dev.example.org", RecordKind::Cname, "x.example.net"),
	]);
	assert!(writes_at(&plan, "*.example.org").is_empty(), "{plan:?}");
	assert_eq!(
		plan.wildcard.reason(),
		"the zone already has a wildcard (*.dev.example.org CNAME, *.example.org A); *.example.org v=spf1 -all is not added, so names that do not exist answer with whatever that wildcard says"
	);
}

#[test]
fn without_a_zone_listing_the_wildcard_reason_says_to_check() {
	let served = served(&[]);
	let plan = build_plan(&PlanInput {
		domain: "example.org",
		served: &served,
		existing: &[],
		journal: None,
		dmarc: &DmarcInputs::default(),
		zone_listed: false,
	});
	assert_eq!(
		plan.wildcard.reason(),
		"*.example.org v=spf1 -all covers names that do not exist; without a provider the zone cannot be read, so add it only if the zone has no wildcard of its own"
	);
}

/// What the zone looks like after `plan` is published on top of `zone`.
fn published(zone: &[DnsRecord], plan: &Plan) -> (Vec<DnsRecord>, Journal) {
	let mut after = zone.to_vec();
	let mut journal = Journal::new("example.org");
	for entry in &plan.entries {
		after.retain(|r| !(r.name == entry.record.name && r.kind == entry.record.kind));
		after.push(entry.record.clone());
		journal.entries.push(JournalEntry {
			record: entry.record.clone(),
			replaced: entry.replaces.clone(),
		});
	}
	(after, journal)
}

#[test]
fn a_second_run_with_nothing_to_do_plans_nothing() {
	let zone = vec![
		a("www.example.org"),
		txt(
			"_dmarc.example.org",
			"v=DMARC1; p=reject; sp=reject; np=reject",
		),
	];
	let first = plan(&zone);
	assert_eq!(first.entries.len(), 3, "{first:?}");
	let (after, journal) = published(&zone, &first);
	let second = plan_with(&after, Some(&journal), &DmarcInputs::default());
	assert!(second.entries.is_empty(), "{second:?}");
	assert_eq!(
		skip_reason(&second, "www.example.org").as_deref(),
		Some("www.example.org already has the null SPF and null MX this command published")
	);
	assert_eq!(
		second.wildcard,
		WildcardDecision::AlreadyPresent {
			reason: "*.example.org already has the null SPF this command published".into()
		}
	);
}

#[test]
fn a_null_spf_the_operator_wrote_is_theirs() {
	// Not in the journal: the operator's own, so the name is theirs too.
	let plan = plan(&[a("old.example.org"), txt("old.example.org", "v=spf1 -all")]);
	assert!(writes_at(&plan, "old.example.org").is_empty());
	assert_eq!(
		skip_reason(&plan, "old.example.org").as_deref(),
		Some("old.example.org has its own SPF record; left as is")
	);
}

#[test]
fn the_json_plan_reads_back_as_the_same_plan() {
	let plan = plan(&[
		a("www.example.org"),
		rec("blog.example.org", RecordKind::Cname, "x.example.net"),
	]);
	let json = serde_json::to_string(&plan).expect("json");
	assert!(json.contains("\"kind\":\"TXT\""), "{json}");
	assert!(json.contains("\"decision\":\"added\""), "{json}");
	let back: Plan = serde_json::from_str(&json).expect("read back");
	assert_eq!(back, plan);
}
