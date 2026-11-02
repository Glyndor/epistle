//! `--undo` withdraws what the ledgers list and nothing else.

use std::time::Duration;

use super::run::{block, harness, publish, read};
use super::support::{rec, txt};
use super::*;
use crate::dns::lockdown::tests::support::Zone;
use crate::dns::reconcile::store;
use crate::dns::reconcile::undo::undo;

fn outcome_of(
	report: &crate::dns::reconcile::undo::UndoReport,
	record: &DnsRecord,
) -> &'static str {
	report
		.entries
		.iter()
		.find(|e| crate::dns::rrset::same_record(&e.record, record))
		.map(|e| e.outcome)
		.unwrap_or("not listed")
}

#[test]
fn undo_removes_epistles_records_and_leaves_the_rest() {
	let h = harness();
	let spf = txt("example.org", "v=spf1 mx -all");
	let mx = rec("example.org", RecordKind::Mx, "10 mail.example.org");
	let srv = rec(
		"_imaps._tcp.example.org",
		RecordKind::Srv,
		"0 1 993 mail.example.org.",
	);
	let theirs = txt("example.org", "google-site-verification=abc");
	let zone = Zone::with(vec![theirs.clone()]);
	let _ = publish(
		&h,
		&zone,
		read(&h, &zone, &[spf.clone(), mx.clone(), srv.clone()]),
	);
	// The operator edits the locator by hand after it was published.
	let edited = rec(
		"_imaps._tcp.example.org",
		RecordKind::Srv,
		"0 1 994 mail.example.org.",
	);
	{
		let mut records = zone.records.lock().unwrap();
		records.retain(|r| r.kind != RecordKind::Srv);
		records.push(edited.clone());
	}
	let dry = block(undo(&h.config, &zone, None, true, Duration::from_secs(5))).expect("undo");
	assert_eq!(outcome_of(&dry, &spf), "remove");
	assert_eq!(outcome_of(&dry, &srv), "absent");
	assert!(zone.snapshot().len() == 4, "a dry run removes nothing");
	let done = block(undo(&h.config, &zone, None, false, Duration::from_secs(5))).expect("undo");
	assert!(done.failure.is_none());
	let now = zone.snapshot();
	let mut expected = vec![theirs, edited];
	expected.sort_by(|a, b| a.value.cmp(&b.value));
	let mut now_sorted = now.clone();
	now_sorted.sort_by(|a, b| a.value.cmp(&b.value));
	assert_eq!(now_sorted, expected, "only epistle's own records go");
	let ledger = store::load(&h.config.data_dir, "example.org").expect("ledger");
	assert!(ledger.entries.is_empty());
}

#[test]
fn undo_leaves_a_dkim_key_in_service() {
	let h = harness();
	let key = txt("s1._domainkey.example.org", "v=DKIM1; k=ed25519; p=AAAA");
	let zone = Zone::default();
	let _ = publish(&h, &zone, read(&h, &zone, std::slice::from_ref(&key)));
	let done = block(undo(&h.config, &zone, None, false, Duration::from_secs(5))).expect("undo");
	assert_eq!(outcome_of(&done, &key), "left");
	assert_eq!(zone.snapshot(), vec![key]);
}
