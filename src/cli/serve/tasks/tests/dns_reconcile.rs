//! The DNS reconcile loop: it runs only in automatic mode, follows
//! `[dns_publish] interval_secs`, and one tick is the same run as
//! `epistle dns publish --yes`.

use std::sync::Arc;
use std::time::Duration;

use super::super::dns_reconcile::{ReconcilePlan, decide, tick};
use crate::config::Config;
use crate::dns::lockdown::tests::support::Zone;
use crate::dns::provider::{DnsRecord, RecordKind};

fn config(dir: &std::path::Path, extra: &str) -> Config {
	toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = {dir:?}\ndomains = ['example.org']\n{extra}"
	))
	.expect("config")
}

const CLOUDFLARE: &str = "[dns]\nprovider = 'cloudflare'\nzone = 'example.org'\ntoken_env = 'EPISTLE_TEST_UNSET_TOKEN'\n";

fn spf() -> DnsRecord {
	DnsRecord::new("example.org", RecordKind::Txt, "v=spf1 mx -all", 3600)
}

fn holds(zone: &Zone, record: &DnsRecord) -> bool {
	zone.snapshot()
		.iter()
		.any(|r| crate::dns::rrset::same_record(r, record))
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
