//! The TXT records the operator supplies: published, kept on a re-run and
//! retired through the ledger when they leave the configuration. The zone is
//! in memory; nothing reaches a real DNS service.

use super::run::{Harness, publish, read_zones};
use super::support::{holds, txt};
use crate::config::Config;
use crate::dns::desired::from_config;
use crate::dns::lockdown::tests::support::Zone;

const TOKEN: &str = "google-site-verification=abc";

fn config_in(dir: &std::path::Path, extra: &str) -> Config {
	toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = {dir:?}\ndomains = ['example.org']\n\
		 [dns]\nprovider = 'cloudflare'\nzone = 'example.org'\ntoken = 'inline-token'\n{extra}"
	))
	.expect("config")
}

fn with_token() -> Harness {
	let dir = tempfile::tempdir().expect("directory");
	let config = config_in(
		dir.path(),
		&format!("[dns_publish]\nextra_txt = [{{ name = 'example.org', value = '{TOKEN}' }}]\n"),
	);
	Harness { _dir: dir, config }
}

/// The same data directory, with another configuration.
fn reconfigured(h: &Harness, extra: &str) -> Harness {
	Harness {
		_dir: tempfile::tempdir().expect("directory"),
		config: config_in(&h.config.data_dir, extra),
	}
}

/// One run: read the zone against the set `h` wants, then apply the plan.
fn run(h: &Harness, zone: &Zone) -> bool {
	let wanted = from_config(&h.config).expect("set").records;
	let survey = read_zones(h, zone, &wanted).expect("read");
	let changed = survey.changes();
	let report = publish(h, zone, survey);
	assert!(report.failure.is_none(), "{:?}", report.failure);
	changed
}

#[test]
fn the_supplied_record_is_published_beside_the_spf_and_a_second_run_changes_nothing() {
	let h = with_token();
	let zone = Zone::with(vec![]);
	assert!(run(&h, &zone), "the first run writes");
	let now = zone.snapshot();
	assert!(holds(&now, &txt("example.org", TOKEN)), "{now:#?}");
	assert!(
		now.iter()
			.any(|r| r.name == "example.org" && r.value.starts_with("v=spf1")),
		"the SPF is still there: {now:#?}"
	);
	assert!(!run(&h, &zone), "the second run changes nothing");
	assert!(holds(&zone.snapshot(), &txt("example.org", TOKEN)));
}

#[test]
fn a_record_that_leaves_the_configuration_is_retired_through_the_ledger() {
	let h = with_token();
	let zone = Zone::with(vec![]);
	run(&h, &zone);
	assert!(holds(&zone.snapshot(), &txt("example.org", TOKEN)));
	let later = reconfigured(&h, "");
	run(&later, &zone);
	let now = zone.snapshot();
	assert!(!holds(&now, &txt("example.org", TOKEN)), "{now:#?}");
	assert!(
		now.iter()
			.any(|r| r.name == "example.org" && r.value.starts_with("v=spf1")),
		"the SPF stays: {now:#?}"
	);
}
