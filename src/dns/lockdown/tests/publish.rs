//! Tests for publishing a plan and undoing it against a zone in memory:
//! the journal holds exactly what went out, `--undo` touches nothing it
//! did not write and puts back the DMARC record it replaced.

use super::support::*;
use super::*;

/// A zone with records the lockdown must never touch.
fn operator_zone() -> Vec<DnsRecord> {
	vec![
		a("example.org"),
		mx("example.org", "10 mail.example.org"),
		txt("example.org", "v=spf1 mx -all"),
		txt("example.org", "google-site-verification=abc"),
		a("mail.example.org"),
		a("www.example.org"),
		txt(
			"_dmarc.example.org",
			"v=DMARC1; p=none; rua=mailto:d@example.org",
		),
	]
}

fn sorted(mut records: Vec<DnsRecord>) -> Vec<String> {
	let mut lines: Vec<String> = records
		.drain(..)
		.map(|r| format!("{} {} {}", r.name, r.kind.as_str(), r.value))
		.collect();
	lines.sort();
	lines
}

async fn publish(
	zone: &Zone,
	plan: &Plan,
	journal: Option<&Journal>,
) -> Result<Journal, PublishFailure> {
	publish_plan(zone, "example.org", plan, journal, &mut |_| Ok(())).await
}

#[tokio::test]
async fn publishing_journals_every_write_and_the_dmarc_it_replaced() {
	let zone = Zone::with(operator_zone());
	let plan = plan(&zone.snapshot());
	let mut saved: Vec<usize> = Vec::new();
	let journal = publish_plan(&zone, "example.org", &plan, None, &mut |j| {
		saved.push(j.entries.len());
		Ok(())
	})
	.await
	.expect("publish");
	assert_eq!(
		saved,
		vec![1, 2, 3, 4],
		"the journal is saved after each write"
	);
	let written: Vec<String> = journal
		.entries
		.iter()
		.map(|e| {
			format!(
				"{} {} {}",
				e.record.name,
				e.record.kind.as_str(),
				e.record.value
			)
		})
		.collect();
	assert_eq!(
		written,
		vec![
			"_dmarc.example.org TXT v=DMARC1; p=quarantine; sp=quarantine; np=reject; rua=mailto:d@example.org",
			"www.example.org TXT v=spf1 -all",
			"www.example.org MX 0 .",
			"*.example.org TXT v=spf1 -all",
		]
	);
	assert_eq!(
		journal.entries[0].replaced,
		Some(txt(
			"_dmarc.example.org",
			"v=DMARC1; p=none; rua=mailto:d@example.org"
		))
	);
	assert!(journal.entries[1..].iter().all(|e| e.replaced.is_none()));
}

#[tokio::test]
async fn a_provider_failure_halfway_leaves_the_journal_with_what_went_out() {
	let zone = Zone {
		fail_on: Some(3),
		..Zone::with(operator_zone())
	};
	let plan = plan(&zone.snapshot());
	let mut last_saved = None;
	let failure = publish_plan(&zone, "example.org", &plan, None, &mut |j| {
		last_saved = Some(j.clone());
		Ok(())
	})
	.await
	.expect_err("the third write fails");
	assert_eq!(
		failure.message,
		"publishing MX www.example.org failed: provider error: rate limited"
	);
	assert_eq!(failure.journal.entries.len(), 2);
	assert_eq!(last_saved.as_ref(), Some(&failure.journal));
	// Undo from that journal brings the zone back exactly.
	let zone = Zone::with(zone.snapshot());
	undo_journal(&zone, "example.org", &failure.journal, false)
		.await
		.expect("undo");
	assert_eq!(sorted(zone.snapshot()), sorted(operator_zone()));
}

#[tokio::test]
async fn a_journal_that_cannot_be_saved_stops_the_next_write() {
	let zone = Zone::with(operator_zone());
	let plan = plan(&zone.snapshot());
	let failure = publish_plan(&zone, "example.org", &plan, None, &mut |_| {
		Err("disk full".into())
	})
	.await
	.expect_err("persist fails");
	assert_eq!(
		*zone.writes.lock().unwrap(),
		1,
		"no write after the failed save"
	);
	assert_eq!(
		failure.message,
		"TXT _dmarc.example.org was published but the journal could not be saved (disk full); remove it by hand if you undo"
	);
}

#[tokio::test]
async fn undo_puts_the_zone_back_as_it_was() {
	let zone = Zone::with(operator_zone());
	let first = plan(&zone.snapshot());
	let journal = publish(&zone, &first, None).await.expect("first run");
	// The second run moves DMARC to reject; the journal keeps the original.
	let second = plan_with(&zone.snapshot(), Some(&journal), &DmarcInputs::default());
	assert_eq!(second.entries.len(), 1, "{second:?}");
	let journal = publish(&zone, &second, Some(&journal))
		.await
		.expect("second run");
	assert_eq!(journal.entries.len(), 4, "{journal:?}");
	let report = undo_journal(&zone, "example.org", &journal, false)
		.await
		.expect("undo");
	assert_eq!(sorted(zone.snapshot()), sorted(operator_zone()));
	assert_eq!(report.deleted.len(), 3);
	assert_eq!(
		report.restored,
		vec![txt(
			"_dmarc.example.org",
			"v=DMARC1; p=none; rua=mailto:d@example.org"
		)]
	);
	assert!(report.changed.is_empty() && report.absent.is_empty());
}

#[tokio::test]
async fn undo_leaves_a_record_the_operator_changed() {
	let zone = Zone::with(operator_zone());
	let journal = publish(&zone, &plan(&zone.snapshot()), None)
		.await
		.expect("publish");
	// The operator turns www into a sender and adds a second MX.
	zone.records
		.lock()
		.unwrap()
		.retain(|r| !(r.name == "www.example.org" && r.kind == RecordKind::Txt));
	zone.records.lock().unwrap().push(txt(
		"www.example.org",
		"v=spf1 include:mailer.example.net -all",
	));
	zone.records
		.lock()
		.unwrap()
		.push(mx("www.example.org", "10 mx.example.net"));
	let report = undo_journal(&zone, "example.org", &journal, false)
		.await
		.expect("undo");
	let www: Vec<String> = sorted(zone.snapshot())
		.into_iter()
		.filter(|line| line.starts_with("www.example.org "))
		.collect();
	assert_eq!(
		www,
		vec![
			"www.example.org A 192.0.2.10",
			"www.example.org MX 0 .",
			"www.example.org MX 10 mx.example.net",
			"www.example.org TXT v=spf1 include:mailer.example.net -all",
		]
	);
	let changed: Vec<(String, Vec<String>)> = report
		.changed
		.iter()
		.map(|c| {
			(
				format!("{} {}", c.record.kind.as_str(), c.record.name),
				c.now.clone(),
			)
		})
		.collect();
	assert_eq!(
		changed,
		vec![
			(
				"MX www.example.org".to_string(),
				vec!["0 .".to_string(), "10 mx.example.net".to_string()]
			),
			(
				"TXT www.example.org".to_string(),
				vec!["v=spf1 include:mailer.example.net -all".to_string()]
			),
		]
	);
}

#[tokio::test]
async fn undo_reports_what_is_already_gone() {
	let zone = Zone::with(vec![a("www.example.org")]);
	let journal = Journal {
		domain: "example.org".into(),
		entries: vec![JournalEntry {
			record: mx("www.example.org", "0 ."),
			replaced: None,
		}],
	};
	let report = undo_journal(&zone, "example.org", &journal, false)
		.await
		.expect("undo");
	assert_eq!(report.absent, vec![mx("www.example.org", "0 .")]);
	assert_eq!(*zone.writes.lock().unwrap(), 0);
}

#[tokio::test]
async fn a_dry_run_undo_writes_nothing() {
	let zone = Zone::with(operator_zone());
	let journal = publish(&zone, &plan(&zone.snapshot()), None)
		.await
		.expect("publish");
	let before = zone.snapshot();
	let writes = *zone.writes.lock().unwrap();
	let report = undo_journal(&zone, "example.org", &journal, true)
		.await
		.expect("dry run");
	assert_eq!(report.deleted.len(), 3);
	assert_eq!(report.restored.len(), 1);
	assert_eq!(zone.snapshot(), before);
	assert_eq!(*zone.writes.lock().unwrap(), writes);
}

#[tokio::test]
async fn an_undo_that_fails_halfway_keeps_what_is_left_to_undo() {
	let zone = Zone::with(operator_zone());
	let journal = publish(&zone, &plan(&zone.snapshot()), None)
		.await
		.expect("publish");
	let zone = Zone {
		fail_on: Some(2),
		..Zone::with(zone.snapshot())
	};
	let failure = undo_journal(&zone, "example.org", &journal, false)
		.await
		.expect_err("second write fails");
	// Newest first: the wildcard went, the null MX failed.
	assert_eq!(
		failure.report.deleted,
		vec![txt("*.example.org", "v=spf1 -all")]
	);
	assert_eq!(failure.remaining.entries, journal.entries[..3].to_vec());
	assert_eq!(
		failure.message,
		"undoing MX www.example.org failed: provider error: rate limited"
	);
}

#[test]
fn a_null_mx_listed_without_its_preference_is_still_ours() {
	assert!(same_record(
		&mx("x.example.org", "0 ."),
		&mx("X.example.org.", ".")
	));
	assert!(!same_record(
		&mx("x.example.org", "0 ."),
		&mx("x.example.org", "10 .")
	));
	assert!(!same_record(
		&mx("x.example.org", "0 ."),
		&mx("x.example.org", "0 mx.example.org")
	));
	assert!(same_record(
		&txt("x.example.org", "v=spf1 -all"),
		&txt("x.example.org", "\"v=spf1 -all\"")
	));
}

#[tokio::test]
async fn a_null_mx_listed_as_a_bare_preference_is_still_ours() {
	// The DigitalOcean, GoDaddy, Namecheap, Porkbun and Spaceship readers
	// cut the trailing dot off an MX target, so the null MX they list comes
	// back as `0 ` or `0`.
	for listed_as in ["0 ", "0"] {
		let zone = Zone::with(operator_zone());
		let journal = publish(&zone, &plan(&zone.snapshot()), None)
			.await
			.expect("publish");
		let listed: Vec<DnsRecord> = zone
			.snapshot()
			.into_iter()
			.map(|mut r| {
				if r.kind == RecordKind::Mx && r.value == NULL_MX {
					r.value = listed_as.to_string();
				}
				r
			})
			.collect();
		let second = plan_with(&listed, Some(&journal), &DmarcInputs::default());
		assert_eq!(
			skip_reason(&second, "www.example.org").as_deref(),
			Some("www.example.org already has the null SPF and null MX this command published"),
			"{listed_as:?}"
		);
		let zone = Zone::with(listed);
		let report = undo_journal(&zone, "example.org", &journal, false)
			.await
			.expect("undo");
		assert!(report.changed.is_empty(), "{listed_as:?}: {report:?}");
		assert_eq!(
			sorted(zone.snapshot()),
			sorted(operator_zone()),
			"{listed_as:?}"
		);
	}
}

#[tokio::test]
async fn undo_puts_back_the_dmarc_record_the_operator_edited_between_runs() {
	use crate::dns::provider::DnsProvider;
	let zone = Zone::with(vec![a("www.example.org")]);
	let first = publish(&zone, &plan(&zone.snapshot()), None)
		.await
		.expect("first run");
	// The first run created the DMARC record; the operator then adds a
	// report address to it, and the second run moves it to reject.
	let edited = txt(
		"_dmarc.example.org",
		"v=DMARC1; p=quarantine; sp=quarantine; np=reject; rua=mailto:d@example.org",
	);
	zone.upsert("example.org", edited.clone())
		.await
		.expect("operator edit");
	let second = plan_with(&zone.snapshot(), Some(&first), &DmarcInputs::default());
	let journal = publish(&zone, &second, Some(&first))
		.await
		.expect("second run");
	let report = undo_journal(&zone, "example.org", &journal, false)
		.await
		.expect("undo");
	assert_eq!(report.restored, vec![edited.clone()]);
	let dmarc: Vec<DnsRecord> = zone
		.snapshot()
		.into_iter()
		.filter(|r| r.name == "_dmarc.example.org")
		.collect();
	assert_eq!(dmarc, vec![edited]);
}

#[allow(unused_imports)]
use super::super::dmarc;
