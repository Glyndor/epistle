//! The DNS reconcile loop: it runs only in automatic mode, follows
//! `[dns_publish] interval_secs`, and one tick is the same run as
//! `epistle dns publish --yes`.

use std::sync::Arc;
use std::time::Duration;

use super::super::dns_reconcile::{
	FIRST_RUN_AFTER, ReconcilePlan, Tick, backoff, backoff_base, build_provider, decide, loop_with,
	tick,
};
use crate::config::Config;
use crate::dns::lockdown::tests::support::Zone;
use crate::dns::provider::{DnsProvider, DnsRecord, ListOp, Op, ProviderError, RecordKind};

fn config(dir: &std::path::Path, extra: &str) -> Config {
	toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = {dir:?}\ndomains = ['example.org']\n{extra}"
	))
	.expect("config")
}

const CLOUDFLARE: &str = "[dns]\nprovider = 'cloudflare'\nzone = 'example.org'\ntoken_env = 'EPISTLE_TEST_UNSET_TOKEN'\n";

/// Two `[[dns]]` entries: one with a credential that is there and one
/// whose `token_env` names a variable that is not set.
const TWO_ZONES: &str = "[[dns]]\nprovider = 'cloudflare'\nzone = 'example.org'\ntoken = 'inline-token'\n\
	[[dns]]\nprovider = 'cloudflare'\nzone = 'other.net'\ntoken_env = 'EPISTLE_TEST_UNSET_TOKEN'\n";

fn spf() -> DnsRecord {
	DnsRecord::new("example.org", RecordKind::Txt, "v=spf1 mx -all", 3600)
}

fn holds(zone: &Zone, record: &DnsRecord) -> bool {
	zone.snapshot()
		.iter()
		.any(|r| crate::dns::rrset::same_record(r, record))
}

/// A provider that works for every zone but one: the zone it cannot list
/// is the one whose `[dns]` entry has no credential.
struct OneBlind {
	inner: Zone,
	blind: String,
}

impl DnsProvider for OneBlind {
	fn upsert(&self, zone: &str, record: DnsRecord) -> Op<'_> {
		self.inner.upsert(zone, record)
	}
	fn delete(&self, zone: &str, record: DnsRecord) -> Op<'_> {
		self.inner.delete(zone, record)
	}
	fn list(&self, zone: &str) -> ListOp<'_> {
		self.inner.list(zone)
	}
	fn publish_snapshot<'a>(
		&'a self,
		zone: &'a str,
	) -> crate::dns::publish::provider::SnapshotOp<'a> {
		if zone == self.blind {
			return Box::pin(async { Err(ProviderError::Unsupported) });
		}
		self.inner.publish_snapshot(zone)
	}
}

/// A provider that never answers.
struct Failing;

impl DnsProvider for Failing {
	fn upsert(&self, _zone: &str, _record: DnsRecord) -> Op<'_> {
		Box::pin(async { Err(ProviderError::Remote("no answer".into())) })
	}
	fn delete(&self, _zone: &str, _record: DnsRecord) -> Op<'_> {
		Box::pin(async { Err(ProviderError::Remote("no answer".into())) })
	}
	fn list(&self, _zone: &str) -> ListOp<'_> {
		Box::pin(async { Err(ProviderError::Remote("no answer".into())) })
	}
}

/// The provider of a run, for a loop whose provider never changes.
fn always(
	provider: Arc<dyn DnsProvider>,
) -> impl FnMut(&Config) -> Result<Arc<dyn DnsProvider>, String> {
	move |_| Ok(Arc::clone(&provider))
}

#[test]
fn manual_mode_runs_no_loop() {
	let dir = tempfile::tempdir().expect("directory");
	assert_eq!(decide(&config(dir.path(), "")), ReconcilePlan::Manual);
	let manual = "[dns]\nprovider = 'manual'\nzone = 'example.org'\n";
	assert_eq!(decide(&config(dir.path(), manual)), ReconcilePlan::Manual);
}

#[test]
fn automatic_mode_runs_every_interval_and_zero_turns_it_off() {
	let dir = tempfile::tempdir().expect("directory");
	assert_eq!(
		decide(&config(dir.path(), CLOUDFLARE)),
		ReconcilePlan::Run {
			every: Duration::from_secs(crate::config::DNS_PUBLISH_DEFAULT_INTERVAL_SECS)
		}
	);
	let off = format!("{CLOUDFLARE}[dns_publish]\ninterval_secs = 0\n");
	assert_eq!(decide(&config(dir.path(), &off)), ReconcilePlan::Off);
	let hourly = format!("{CLOUDFLARE}[dns_publish]\ninterval_secs = 3600\n");
	assert_eq!(
		decide(&config(dir.path(), &hourly)),
		ReconcilePlan::Run {
			every: Duration::from_secs(3600)
		}
	);
}

#[tokio::test]
async fn a_tick_publishes_what_is_missing_and_keeps_a_foreign_record() {
	let dir = tempfile::tempdir().expect("directory");
	let config = config(dir.path(), CLOUDFLARE);
	let theirs = DnsRecord::new(
		"_imaps._tcp.example.org",
		RecordKind::Srv,
		"0 1 993 imap.example.net.",
		3600,
	);
	let zone = Arc::new(Zone::with(vec![theirs.clone()]));
	tick(&config, zone.as_ref()).await;
	assert!(holds(&zone, &spf()), "the missing SPF is published");
	assert!(holds(&zone, &theirs), "a record somebody else wrote stays");
	let writes = *zone.writes.lock().unwrap();
	tick(&config, zone.as_ref()).await;
	assert_eq!(
		*zone.writes.lock().unwrap(),
		writes,
		"a second tick changes nothing"
	);
}

#[tokio::test]
async fn a_tick_while_a_publish_holds_the_ledger_writes_nothing() {
	let dir = tempfile::tempdir().expect("directory");
	let config = config(dir.path(), CLOUDFLARE);
	let zone = Arc::new(Zone::default());
	let _held = crate::dns::reconcile::store::lock(&config.data_dir, Duration::ZERO)
		.expect("lock")
		.expect("free");
	tick(&config, zone.as_ref()).await;
	assert_eq!(*zone.writes.lock().unwrap(), 0);
}

/// A zone whose credential is missing does not stop the other zones: the
/// tick publishes the zone that can be published and leaves the other one
/// alone.
#[tokio::test]
async fn a_tick_with_a_broken_credential_publishes_the_other_zone() {
	let dir = tempfile::tempdir().expect("directory");
	let config = toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = {:?}\ndomains = ['example.org', 'other.net']\n{TWO_ZONES}",
		dir.path()
	))
	.expect("config");
	let provider = OneBlind {
		inner: Zone::default(),
		blind: "other.net".to_string(),
	};
	let outcome = tick(&config, &provider).await;
	assert_eq!(outcome, Tick::Failed, "the run did not go through");
	assert!(
		holds(&provider.inner, &spf()),
		"the zone that could be published is published"
	);
}

/// The wait after a failed run grows, and it never grows past the cap.
#[test]
fn the_backoff_doubles_up_to_the_cap() {
	let every = Duration::from_secs(600);
	assert_eq!(backoff_base(every, 1), every);
	assert_eq!(backoff_base(every, 2), every * 2);
	assert_eq!(backoff_base(every, 3), every * 4);
	assert_eq!(backoff_base(every, 4), every * 8);
	assert_eq!(backoff_base(every, 40), every * 8);
	// The wait never goes below the configured interval, whatever the
	// interval is.
	let week = Duration::from_secs(604_800);
	assert_eq!(backoff_base(week, 1), week);
	assert_eq!(backoff_base(week, 40), week);
}

/// The wait is spread around its base, so a fleet of servers does not ask
/// the provider at the same second.
#[test]
fn the_backoff_is_spread_around_its_base() {
	let every = Duration::from_secs(600);
	for failures in 1..6 {
		let base = backoff_base(every, failures);
		let wait = backoff(every, failures);
		assert!(
			wait >= base * 4 / 5 && wait <= base * 6 / 5,
			"wait {wait:?} is not around the base {base:?}"
		);
	}
}

/// A provider that fails is asked less often: the interval between two
/// attempts grows with every failure.
#[tokio::test]
async fn a_provider_that_fails_waits_longer_every_time() {
	let dir = tempfile::tempdir().expect("directory");
	let config = config(dir.path(), CLOUDFLARE);
	let mut waits: Vec<Duration> = Vec::new();
	let mut runs = 0u32;
	loop_with(&config, always(Arc::new(Failing)), |delay| {
		waits.push(delay);
		runs += 1;
		let keep = runs < 5;
		async move { keep }
	})
	.await;
	assert_eq!(waits.len(), 5);
	// The first wait is the wait before the first run.
	assert_eq!(waits[0], FIRST_RUN_AFTER);
	let every = interval_of(&config);
	for (index, failures) in [1u32, 2, 3, 4].iter().enumerate() {
		let base = backoff_base(every, *failures);
		let wait = waits[index + 1];
		assert!(
			wait >= base * 4 / 5 && wait <= base * 6 / 5,
			"wait {index} is {wait:?}, not around the base {base:?}"
		);
	}
	// The interval between two attempts grows.
	assert!(waits[2] > waits[1], "{:?}", waits);
	assert!(waits[3] > waits[2], "{:?}", waits);
}

/// A run that goes through resets the wait: the next one is the
/// configured interval again.
#[tokio::test]
async fn a_run_that_goes_through_resets_the_wait() {
	let dir = tempfile::tempdir().expect("directory");
	let config = config(dir.path(), CLOUDFLARE);
	let zone: Arc<dyn DnsProvider> = Arc::new(Zone::default());
	let mut waits: Vec<Duration> = Vec::new();
	let mut runs = 0u32;
	loop_with(&config, always(Arc::clone(&zone)), |delay| {
		waits.push(delay);
		runs += 1;
		let keep = runs < 3;
		async move { keep }
	})
	.await;
	let every = interval_of(&config);
	assert_eq!(waits[0], FIRST_RUN_AFTER);
	assert_eq!(
		waits[1], every,
		"a run that went through waits the interval"
	);
	assert_eq!(waits[2], every, "and again");
}

/// The interval the loop runs at.
fn interval_of(config: &Config) -> Duration {
	match decide(config) {
		ReconcilePlan::Run { every } => every,
		_ => panic!("the loop runs"),
	}
}

/// The provider is built again on every run: a credential that was
/// rotated, or created after the server started, is picked up without a
/// restart, and a build that fails keeps the provider of the last run
/// writing.
#[tokio::test]
async fn a_credential_that_appears_after_the_start_is_picked_up() {
	const TOKEN: &str = "EPISTLE_TEST_LATE_TOKEN";
	const VALUE: &str = "the-credential-that-came-late";
	let dir = tempfile::tempdir().expect("directory");
	let config = config(
		dir.path(),
		&format!("[dns]\nprovider = 'cloudflare'\nzone = 'example.org'\ntoken_env = '{TOKEN}'\n"),
	);
	// The credential is not there yet: the configuration builds no
	// provider, and says which piece is missing without printing one.
	unsafe { std::env::remove_var(TOKEN) };
	let problem = match build_provider(&config) {
		Ok(_) => panic!("no provider without a credential"),
		Err(reason) => reason,
	};
	assert!(problem.contains(TOKEN), "{problem}");
	assert!(!problem.contains(VALUE), "{problem}");

	let zone = Arc::new(Zone::default());
	let provider: Arc<dyn DnsProvider> = zone.clone();
	let mut runs = 0u32;
	let mut published = 0u32;
	loop_with(
		&config,
		|config| {
			// The provider the configuration builds would talk to the
			// network; the test keeps the decision the configuration
			// makes and swaps the provider for a zone in memory.
			build_provider(config).map(|_| Arc::clone(&provider))
		},
		|_delay| {
			runs += 1;
			match runs {
				1 => assert_eq!(
					*zone.writes.lock().unwrap(),
					0,
					"the first run had no provider and wrote nothing"
				),
				// The credential appears after the first run.
				2 => unsafe { std::env::set_var(TOKEN, VALUE) },
				3 => {
					// The credential is gone again and the zone is empty:
					// the provider of the last run must write anyway.
					unsafe { std::env::remove_var(TOKEN) };
					zone.records.lock().unwrap().clear();
					published = *zone.writes.lock().unwrap();
					assert!(published > 0, "the run that found the credential published");
				}
				4 => assert!(
					*zone.writes.lock().unwrap() > published,
					"the provider of the last run kept writing"
				),
				_ => unsafe { std::env::remove_var(TOKEN) },
			}
			let keep = runs < 5;
			async move { keep }
		},
	)
	.await;
	unsafe { std::env::remove_var(TOKEN) };
	assert!(
		holds(&zone, &spf()),
		"the records of the configuration are published"
	);
}
