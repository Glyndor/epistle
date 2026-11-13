//! A zone another account changes between the read and the write. The
//! guarded write is refused, nothing of the plan lands over what the other
//! account wrote, and the ledger claims only what went out.

use std::sync::Mutex;

use super::run::{harness, publish, read};
use super::support::{holds, rec, txt};
use super::*;
use crate::dns::provider::DnsProvider;
use crate::dns::publish::FakeGuardedProvider;
use crate::dns::reconcile::store;

/// A zone that takes a foreign write just before the `nth` guarded change
/// reaches it, the way a second operator or a script does between the
/// read of the plan and the write.
struct Meddled {
	inner: FakeGuardedProvider,
	intruder: DnsRecord,
	/// The guarded changes still to let through before the foreign write.
	allow: Mutex<usize>,
}

impl DnsProvider for Meddled {
	fn upsert(&self, zone: &str, record: DnsRecord) -> crate::dns::provider::Op<'_> {
		self.inner.upsert(zone, record)
	}
	fn delete(&self, zone: &str, record: DnsRecord) -> crate::dns::provider::Op<'_> {
		self.inner.delete(zone, record)
	}
	fn list(&self, zone: &str) -> crate::dns::provider::ListOp<'_> {
		self.inner.list(zone)
	}
	fn publish_snapshot<'a>(
		&'a self,
		zone: &'a str,
	) -> crate::dns::publish::provider::SnapshotOp<'a> {
		self.inner.publish_snapshot(zone)
	}
	fn apply_guarded<'a>(
		&'a self,
		zone: &'a str,
		change: crate::dns::publish::Change,
	) -> crate::dns::publish::provider::ReceiptOp<'a> {
		Box::pin(async move {
			let meddle = {
				let mut allow = self.allow.lock().expect("allow");
				if *allow == 0 {
					true
				} else {
					*allow -= 1;
					false
				}
			};
			if meddle {
				self.inner
					.upsert(zone, self.intruder.clone())
					.await
					.expect("the foreign write");
			}
			self.inner.apply_guarded(zone, change).await
		})
	}
	fn lookup_operation<'a>(
		&'a self,
		operation_id: &'a str,
	) -> crate::dns::publish::provider::OperationOp<'a> {
		self.inner.lookup_operation(operation_id)
	}
}

fn spf() -> DnsRecord {
	txt("example.org", "v=spf1 mx -all")
}

fn mx() -> DnsRecord {
	rec("example.org", RecordKind::Mx, "10 mail.example.org")
}

fn zone(allow: usize) -> (Meddled, DnsRecord, DnsRecord) {
	let theirs = txt("example.org", "google-site-verification=abc");
	let intruder = txt("_acme-challenge.example.org", "somebody-elses-token");
	let provider = Meddled {
		inner: FakeGuardedProvider::holding(vec![theirs.clone()]),
		intruder: intruder.clone(),
		allow: Mutex::new(allow),
	};
	(provider, theirs, intruder)
}

#[test]
fn a_zone_changed_before_the_first_write_takes_nothing_of_the_plan() {
	let h = harness();
	let (provider, theirs, intruder) = zone(0);
	let survey = read(&h, &provider, &[spf(), mx()]);
	let report = publish(&h, &provider, survey);
	let failure = report.failure.expect("the run stops");
	assert!(
		failure.contains("the zone changed since it was read; nothing was written"),
		"{failure}"
	);
	assert!(report.applied.is_empty());
	let now = provider.inner.records();
	assert!(holds(&now, &theirs) && holds(&now, &intruder), "{now:?}");
	assert!(!holds(&now, &spf()) && !holds(&now, &mx()), "{now:?}");
	// Nothing went out, so the ledger claims nothing and the next run plans the whole set.
	let ledger = store::load(&h.config.data_dir, "example.org");
	assert!(
		ledger.map_or(true, |l| !l.owns(&spf()) && !l.owns(&mx())),
		"the ledger claims a record that never went out"
	);
	let next = read(&h, &provider, &[spf(), mx()]);
	assert_eq!(next.writes(), 2);
}

#[test]
fn a_zone_changed_after_the_first_write_stops_the_run_with_only_the_first_claimed() {
	let h = harness();
	let (provider, theirs, intruder) = zone(1);
	let survey = read(&h, &provider, &[spf(), mx()]);
	let report = publish(&h, &provider, survey);
	let failure = report.failure.expect("the run stops");
	assert!(
		failure.contains("the zone changed since it was read"),
		"{failure}"
	);
	assert_eq!(report.applied.len(), 1, "{:?}", report.applied);
	let written = report.applied[0].1.record.clone();
	let other = if holds(std::slice::from_ref(&written), &spf()) {
		mx()
	} else {
		spf()
	};
	let now = provider.inner.records();
	assert!(holds(&now, &written) && holds(&now, &theirs) && holds(&now, &intruder));
	assert!(!holds(&now, &other), "the refused change landed: {now:?}");
	let ledger = store::load(&h.config.data_dir, "example.org").expect("ledger");
	assert!(ledger.owns(&written), "the ledger forgot what went out");
	assert!(!ledger.owns(&other), "the ledger claims what was refused");
}

#[test]
fn the_same_zone_that_nobody_touches_takes_the_whole_plan() {
	let h = harness();
	let (provider, theirs, _) = zone(usize::MAX);
	let report = publish(&h, &provider, read(&h, &provider, &[spf(), mx()]));
	assert!(report.failure.is_none(), "{:?}", report.failure);
	let now = provider.inner.records();
	assert!(holds(&now, &theirs) && holds(&now, &spf()) && holds(&now, &mx()));
}
