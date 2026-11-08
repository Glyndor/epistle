//! `--undo` withdraws what the ledgers list and nothing else.

use std::time::Duration;

use super::run::{block, harness, publish, read};
use super::support::{Racing, holds, rec, txt};
use super::*;
use crate::dns::lockdown::tests::support::Zone;
use crate::dns::provider::DnsProvider;
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

/// A record another account writes between the listing and the removal is
/// still there when the removal is done: `--undo` takes the record epistle
/// published and nothing else.
#[test]
fn undo_leaves_a_record_another_account_wrote_in_the_meantime() {
	let h = harness();
	let spf = txt("example.org", "v=spf1 mx -all");
	let theirs = txt("example.org", "v=spf1 include:_spf.example.net -all");
	let zone = Racing {
		zone: Zone::default(),
		foreign: theirs.clone(),
	};
	let _ = publish(&h, &zone, read(&h, &zone, std::slice::from_ref(&spf)));
	let done = block(undo(&h.config, &zone, None, false, Duration::from_secs(5))).expect("undo");
	assert_eq!(outcome_of(&done, &spf), "remove");
	let now = zone.zone.snapshot();
	assert!(
		!holds(&now, &spf),
		"the record epistle published goes: {:#?}",
		now
	);
	assert!(
		holds(&now, &theirs),
		"a record another account wrote must survive: {:#?}",
		now
	);
}

/// A record that shares its place with a record another account wrote is
/// left: taking it would take the other one with it.
#[test]
fn undo_leaves_a_record_that_shares_its_place_with_another_account() {
	let h = harness();
	let spf = txt("example.org", "v=spf1 mx -all");
	let theirs = txt("example.org", "v=spf1 include:_spf.example.net -all");
	let zone = Zone::default();
	let _ = publish(&h, &zone, read(&h, &zone, std::slice::from_ref(&spf)));
	// Another account publishes an SPF at the same name: both records sit
	// in the same place.
	zone.records.lock().unwrap().push(theirs.clone());
	let done = block(undo(&h.config, &zone, None, false, Duration::from_secs(5))).expect("undo");
	assert_eq!(outcome_of(&done, &spf), "left");
	assert!(done.failure.is_none(), "nothing failed: {done:?}");
	let now = zone.snapshot();
	assert!(
		holds(&now, &spf),
		"the record epistle published stays: {now:#?}"
	);
	assert!(
		holds(&now, &theirs),
		"the record another account wrote stays: {now:#?}"
	);
	let ledger = store::load(&h.config.data_dir, "example.org").expect("ledger");
	assert!(
		ledger.owns(&spf),
		"the ledger still lists what epistle published"
	);
}

/// A provider that takes the ledger away when the record is removed: the
/// save that follows the removal cannot land.
struct Unsavable {
	/// The zone the record lives in.
	zone: Zone,
	/// The ledger the save needs.
	ledger: std::path::PathBuf,
}

impl DnsProvider for Unsavable {
	fn upsert(&self, zone: &str, record: DnsRecord) -> crate::dns::provider::Op<'_> {
		self.zone.upsert(zone, record)
	}
	fn delete(&self, zone: &str, record: DnsRecord) -> crate::dns::provider::Op<'_> {
		self.zone.delete(zone, record)
	}
	fn delete_exact(&self, _zone: &str, record: DnsRecord) -> crate::dns::provider::Op<'_> {
		let zone = &self.zone;
		let ledger = self.ledger.clone();
		Box::pin(async move {
			// The record goes out of the zone.
			zone.records
				.lock()
				.unwrap()
				.retain(|r| !crate::dns::rrset::same_record(r, &record));
			// The ledger cannot be saved any more: a directory takes the
			// name of the ledger, and the rename over it fails.
			std::fs::remove_file(&ledger).expect("the ledger is taken away");
			std::fs::create_dir(&ledger).expect("the directory takes its place");
			Ok(())
		})
	}
	fn list(&self, zone: &str) -> crate::dns::provider::ListOp<'_> {
		self.zone.list(zone)
	}
}

/// The record is out of the zone and the ledger cannot be saved: the report
/// still says what went, so the operator knows what the zone holds now.
#[test]
fn undo_reports_what_it_removed_when_the_ledger_cannot_be_saved() {
	let h = harness();
	let spf = txt("example.org", "v=spf1 mx -all");
	let zone = Unsavable {
		zone: Zone::default(),
		ledger: store::path(&h.config.data_dir, "example.org").expect("path"),
	};
	let _ = publish(&h, &zone, read(&h, &zone, std::slice::from_ref(&spf)));
	let done = block(undo(&h.config, &zone, None, false, Duration::from_secs(5)))
		.expect("the report is not lost with the ledger");
	assert_eq!(
		outcome_of(&done, &spf),
		"remove",
		"the report says what went: {done:?}"
	);
	let failure = done.failure.expect("the save error is told");
	assert!(
		failure.contains("the ledger could not be saved"),
		"the failure names the ledger: {failure}"
	);
	assert!(
		!holds(&zone.zone.snapshot(), &spf),
		"the record is out of the zone"
	);
}
