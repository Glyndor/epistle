//! A whole run against a zone in memory: read, plan, apply, read again.
//! Nothing reaches a real DNS service.

use std::sync::Arc;
use std::time::Duration;

use super::support::{LostAnswer, holds, rec, txt};
use super::*;
use crate::config::Config;
use crate::dns::lockdown::tests::support::Zone;
use crate::dns::provider::DnsProvider;
use crate::dns::publish::{FakeGuardedProvider, OperationOutcome};
use crate::dns::reconcile::survey::{Context, Survey, survey};
use crate::dns::reconcile::{apply, store};
use crate::dns::records::PublishRecord;

pub(crate) struct Harness {
	pub(crate) _dir: tempfile::TempDir,
	pub(crate) config: Config,
}

pub(crate) fn harness() -> Harness {
	let dir = tempfile::tempdir().expect("directory");
	let config: Config = toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = {:?}\ndomains = ['example.org']\n\
		 [dns]\nprovider = 'cloudflare'\nzone = 'example.org'\ntoken = 'inline-token'\n",
		dir.path()
	))
	.expect("config");
	Harness { _dir: dir, config }
}

/// A configuration with two `[[dns]]` entries: one whose credential is
/// there and one whose `token_env` names a variable that is not set. The
/// entry without a credential is the one the provider cannot use.
pub(crate) fn harness_two_zones() -> Harness {
	let dir = tempfile::tempdir().expect("directory");
	let config: Config = toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = {:?}\ndomains = ['example.org', 'other.net']\n\
		 [[dns]]\nprovider = 'cloudflare'\nzone = 'example.org'\ntoken = 'inline-token'\n\
		 [[dns]]\nprovider = 'cloudflare'\nzone = 'other.net'\ntoken_env = 'EPISTLE_TEST_UNSET_TOKEN'\n",
		dir.path()
	))
	.expect("config");
	Harness { _dir: dir, config }
}

pub(crate) fn needed(records: &[DnsRecord]) -> Vec<PublishRecord> {
	records
		.iter()
		.map(|record| PublishRecord {
			zone: "example.org".into(),
			record: record.clone(),
		})
		.collect()
}

pub(crate) fn read(h: &Harness, provider: &dyn DnsProvider, wanted: &[DnsRecord]) -> Survey {
	read_scoped(h, provider, wanted, None).expect("the zone is read")
}

pub(crate) fn read_scoped(
	h: &Harness,
	provider: &dyn DnsProvider,
	wanted: &[DnsRecord],
	domain: Option<&str>,
) -> Result<Survey, String> {
	read_with(h, provider, wanted, domain, None)
}

pub(crate) fn read_with(
	h: &Harness,
	provider: &dyn DnsProvider,
	wanted: &[DnsRecord],
	domain: Option<&str>,
	incomplete: Option<&str>,
) -> Result<Survey, String> {
	let needed = needed(wanted);
	let ctx = Context {
		config: &h.config,
		provider,
		needed: &needed,
		domain,
		timeout: Duration::from_secs(5),
		incomplete,
	};
	block(survey(&ctx))
}

/// Read the zones of a survey whose records name their own zone.
pub(crate) fn read_zones(
	h: &Harness,
	provider: &dyn DnsProvider,
	wanted: &[PublishRecord],
) -> Result<Survey, String> {
	let ctx = Context {
		config: &h.config,
		provider,
		needed: wanted,
		domain: None,
		timeout: Duration::from_secs(5),
		incomplete: None,
	};
	block(survey(&ctx))
}

pub(crate) fn publish(h: &Harness, provider: &dyn DnsProvider, survey: Survey) -> apply::Report {
	let target = apply::Target {
		provider,
		data_dir: &h.config.data_dir,
		hostname: &h.config.hostname,
		timeout: Duration::from_secs(5),
		now: 1_800_000_000,
	};
	block(apply::apply(&target, survey.zones))
}

pub(crate) fn block<T>(future: impl Future<Output = T>) -> T {
	tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()
		.expect("runtime")
		.block_on(future)
}

fn spf() -> DnsRecord {
	txt("example.org", "v=spf1 mx -all")
}

fn mx() -> DnsRecord {
	rec("example.org", RecordKind::Mx, "10 mail.example.org")
}

fn pop3() -> DnsRecord {
	rec(
		"_pop3s._tcp.example.org",
		RecordKind::Srv,
		"0 1 995 mail.example.org.",
	)
}

#[test]
fn a_run_creates_what_is_missing_and_a_second_run_changes_nothing() {
	let h = harness();
	let zone = Zone::with(vec![rec("example.org", RecordKind::Ns, "ns1.example.net")]);
	let report = publish(&h, &zone, read(&h, &zone, &[spf(), mx()]));
	assert!(report.failure.is_none(), "{:?}", report.failure);
	assert_eq!(report.applied.len(), 2);
	let now = zone.snapshot();
	assert!(holds(&now, &spf()) && holds(&now, &mx()));
	let ledger = store::load(&h.config.data_dir, "example.org").expect("ledger");
	assert!(ledger.owns(&spf()) && ledger.owns(&mx()));
	let again = read(&h, &zone, &[spf(), mx()]);
	assert!(!again.changes(), "a second run must change nothing");
	let writes = *zone.writes.lock().unwrap();
	let _ = publish(&h, &zone, again);
	assert_eq!(*zone.writes.lock().unwrap(), writes);
}

#[test]
fn a_foreign_record_in_the_way_is_never_written_over() {
	let h = harness();
	let theirs = txt("example.org", "v=spf1 include:_spf.example.net -all");
	let zone = Zone::with(vec![theirs.clone()]);
	let report = publish(&h, &zone, read(&h, &zone, &[spf()]));
	assert!(report.applied.is_empty());
	assert_eq!(zone.snapshot(), vec![theirs]);
	assert_eq!(*zone.writes.lock().unwrap(), 0);
}

#[test]
fn a_service_turned_off_loses_only_the_locator_epistle_published() {
	let h = harness();
	let theirs = rec(
		"_imap._tcp.example.org",
		RecordKind::Srv,
		"0 1 143 imap.example.net.",
	);
	let zone = Zone::with(vec![theirs.clone()]);
	let _ = publish(&h, &zone, read(&h, &zone, &[pop3()]));
	assert!(holds(&zone.snapshot(), &pop3()));
	// POP3 turned off: nothing needs the locator now.
	let report = publish(&h, &zone, read(&h, &zone, &[]));
	assert!(report.failure.is_none(), "{:?}", report.failure);
	let now = zone.snapshot();
	assert!(!holds(&now, &pop3()), "epistle's own locator must go");
	assert!(
		holds(&now, &theirs),
		"a locator epistle did not write must stay"
	);
	let ledger = store::load(&h.config.data_dir, "example.org").expect("ledger");
	assert!(ledger.entries.is_empty());
}

#[test]
fn a_provider_that_cannot_list_leaves_the_zone_alone() {
	struct Blind(Zone);
	impl DnsProvider for Blind {
		fn upsert(&self, zone: &str, record: DnsRecord) -> crate::dns::provider::Op<'_> {
			self.0.upsert(zone, record)
		}
		fn delete(&self, zone: &str, record: DnsRecord) -> crate::dns::provider::Op<'_> {
			self.0.delete(zone, record)
		}
		fn list(&self, _zone: &str) -> crate::dns::provider::ListOp<'_> {
			Box::pin(async { Err(crate::dns::provider::ProviderError::Unsupported) })
		}
	}
	let h = harness();
	let blind = Blind(Zone::default());
	let read = read_scoped(&h, &blind, &[spf()], None).expect("the zone is left alone");
	assert_eq!(read.failures.len(), 1, "{:#?}", read.failures);
	assert!(
		read.failures[0].reason.contains("cannot list"),
		"{:#?}",
		read.failures
	);
	assert!(
		read.zones.is_empty(),
		"a zone that cannot be listed is not planned"
	);
	assert_eq!(*blind.0.writes.lock().unwrap(), 0);
}

/// A zone whose provider cannot be used is left alone and the other zones
/// are published: one entry with a broken credential must not stop every
/// other domain from being published, and the reason must name the
/// credential that is missing instead of the provider's capability.
#[test]
fn a_zone_whose_credential_is_missing_does_not_stop_the_other_zones() {
	/// A provider that works for every zone but one.
	struct OneZone {
		inner: Zone,
		blind: String,
	}
	impl DnsProvider for OneZone {
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
			if zone == self.blind {
				return Box::pin(async { Err(crate::dns::provider::ProviderError::Unsupported) });
			}
			self.inner.publish_snapshot(zone)
		}
	}
	let h = harness_two_zones();
	let provider = OneZone {
		inner: Zone::default(),
		blind: "other.net".to_string(),
	};
	let wanted = vec![
		PublishRecord {
			zone: "example.org".into(),
			record: spf(),
		},
		PublishRecord {
			zone: "other.net".into(),
			record: txt("other.net", "v=spf1 mx -all"),
		},
	];
	let survey = read_zones(&h, &provider, &wanted).expect("the healthy zone is read");
	assert_eq!(survey.failures.len(), 1, "{:#?}", survey.failures);
	let failure = &survey.failures[0];
	assert_eq!(failure.zone, "other.net");
	assert!(
		failure.reason.contains("EPISTLE_TEST_UNSET_TOKEN"),
		"the reason names the credential that is missing: {}",
		failure.reason
	);
	assert!(
		!failure.reason.contains("cannot list"),
		"the reason is not the provider's capability: {}",
		failure.reason
	);
	assert_eq!(survey.zones.len(), 1, "the other zone is planned");
	assert_eq!(survey.zones[0].plan.zone, "example.org");
	// The healthy zone is published all the same.
	let report = publish(&h, &provider, survey);
	assert!(report.failure.is_none(), "{:?}", report.failure);
	assert_eq!(report.applied.len(), 1);
	assert!(holds(&provider.inner.snapshot(), &spf()));
}

#[test]
fn a_delegated_name_gets_nothing() {
	let h = harness();
	let sub = txt("sub.example.org", "v=spf1 mx -all");
	let zone = Zone::with(vec![rec(
		"sub.example.org",
		RecordKind::Ns,
		"ns1.example.com",
	)]);
	let report = publish(&h, &zone, read(&h, &zone, &[sub]));
	assert!(report.applied.is_empty());
	assert_eq!(*zone.writes.lock().unwrap(), 0);
}

#[test]
fn a_failed_write_stops_the_run_and_the_ledger_claims_nothing() {
	let h = harness();
	let zone = Zone {
		fail_on: Some(1),
		..Zone::default()
	};
	let report = publish(&h, &zone, read(&h, &zone, &[spf(), mx()]));
	assert!(report.failure.is_some());
	assert!(report.applied.is_empty());
	assert!(zone.snapshot().is_empty());
	// The write failed, so the ledger does not claim the record: the next
	// run creates it again, and forgets nothing epistle did write.
	let next = read(&h, &zone, &[spf(), mx()]);
	assert_eq!(next.writes(), 2);
}

#[test]
fn the_guarded_path_writes_the_exact_set_and_keeps_foreign_values() {
	let h = harness();
	let theirs = txt("example.org", "google-site-verification=abc");
	let provider = Arc::new(FakeGuardedProvider::holding(vec![theirs.clone()]));
	let report = publish(
		&h,
		provider.as_ref(),
		read(&h, provider.as_ref(), &[spf(), mx()]),
	);
	assert!(report.failure.is_none(), "{:?}", report.failure);
	let now = provider.records();
	assert!(holds(&now, &theirs) && holds(&now, &spf()) && holds(&now, &mx()));
	assert!(!read(&h, provider.as_ref(), &[spf(), mx()]).changes());
}

/// A guarded write whose answer was lost is resolved by the lookup of the
/// operation: the change went through, and the run goes on.
#[test]
fn a_guarded_write_whose_answer_was_lost_is_resolved() {
	let h = harness();
	let provider = Arc::new(LostAnswer {
		inner: FakeGuardedProvider::holding(Vec::new()),
		outcome: OperationOutcome::Applied,
	});
	let report = publish(
		&h,
		provider.as_ref(),
		read(&h, provider.as_ref(), &[spf(), mx()]),
	);
	assert!(report.failure.is_none(), "{:?}", report.failure);
	let now = provider.inner.records();
	assert!(holds(&now, &spf()) && holds(&now, &mx()));
	let ledger = store::load(&h.config.data_dir, "example.org").expect("ledger");
	assert!(
		ledger.owns(&spf()) && ledger.owns(&mx()),
		"the ledger claims what went out"
	);
}

/// A guarded write the lookup of the operation does not confirm stops the
/// run: nothing else is written until it is resolved.
#[test]
fn a_guarded_write_the_lookup_does_not_confirm_stops_the_run() {
	let h = harness();
	let provider = Arc::new(LostAnswer {
		inner: FakeGuardedProvider::holding(Vec::new()),
		outcome: OperationOutcome::NotApplied,
	});
	let report = publish(
		&h,
		provider.as_ref(),
		read(&h, provider.as_ref(), &[spf(), mx()]),
	);
	let failure = report.failure.expect("the run stops");
	assert!(failure.contains("did not confirm"), "{failure}");
	assert!(
		!holds(&provider.inner.records(), &mx()),
		"nothing else is written until the lost answer is resolved"
	);
}

#[test]
fn a_published_tlsa_value_is_known_to_the_certificate_refresh() {
	let h = harness();
	let tlsa = rec("_25._tcp.mail.example.org", RecordKind::Tlsa, "3 0 1 abcd");
	let zone = Zone::default();
	let _ = publish(&h, &zone, read(&h, &zone, std::slice::from_ref(&tlsa)));
	let state = crate::dns::tlsa::State::load(&h.config.data_dir, "mail.example.org");
	assert_eq!(state.managed, vec!["3 0 1 abcd".to_string()]);
}

#[test]
fn a_run_with_an_incomplete_set_removes_nothing() {
	let h = harness();
	let zone = Zone::default();
	let _ = publish(&h, &zone, read(&h, &zone, &[pop3()]));
	let survey = read_with(&h, &zone, &[], None, Some("cannot load DKIM key")).expect("read");
	assert_eq!(survey.writes(), 0);
	let _ = publish(&h, &zone, survey);
	assert!(
		holds(&zone.snapshot(), &pop3()),
		"a short set must not retire"
	);
}

#[test]
fn a_second_publisher_does_not_get_the_lock() {
	let h = harness();
	let held = store::lock(&h.config.data_dir)
		.expect("lock")
		.expect("free");
	assert!(
		store::lock(&h.config.data_dir).expect("lock").is_none(),
		"the loop and the command must not write at once"
	);
	drop(held);
	assert!(store::lock(&h.config.data_dir).expect("lock").is_some());
}

#[test]
fn a_zone_name_that_is_not_a_dns_name_has_no_ledger_path() {
	let h = harness();
	assert!(store::path(&h.config.data_dir, "../etc").is_err());
	assert!(store::path(&h.config.data_dir, "example.org").is_ok());
}

#[test]
fn a_write_whose_answer_was_lost_is_still_epistles_at_the_next_run() {
	// The provider applies the write and the answer never arrives.
	struct Lost(Zone);
	impl DnsProvider for Lost {
		fn upsert(&self, zone: &str, record: DnsRecord) -> crate::dns::provider::Op<'_> {
			let applied = self.0.upsert(zone, record);
			Box::pin(async move {
				applied.await?;
				Err(crate::dns::provider::ProviderError::Remote(
					"no answer within 5 seconds".into(),
				))
			})
		}
		fn delete(&self, zone: &str, record: DnsRecord) -> crate::dns::provider::Op<'_> {
			self.0.delete(zone, record)
		}
		fn list(&self, zone: &str) -> crate::dns::provider::ListOp<'_> {
			self.0.list(zone)
		}
	}
	let h = harness();
	let lost = Lost(Zone::default());
	let report = publish(&h, &lost, read(&h, &lost, &[spf()]));
	assert!(report.failure.is_some());
	let next = read(&h, &lost, &[spf()]);
	assert_eq!(
		next.zones[0].plan.entries[0].action,
		Action::Present,
		"the record went out and is epistle's own, not somebody else's"
	);
}
