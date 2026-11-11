//! The null SPF and null MX as state: a run against a zone in memory
//! publishes them, a later run covers what was added since, and what stops
//! needing them loses them. Nothing reaches a real DNS service.

use std::path::Path;

use super::run::{Harness, publish, read, read_scoped};
use super::support::{holds, rec, txt};
use super::*;
use crate::config::Config;
use crate::dns::lockdown::tests::support::{Zone, a};
use crate::dns::reconcile::store;

fn spf_null(name: &str) -> DnsRecord {
	txt(name, "v=spf1 -all")
}

fn mx_null(name: &str) -> DnsRecord {
	rec(name, RecordKind::Mx, "0 .")
}

fn apex() -> Vec<DnsRecord> {
	vec![
		txt("example.org", "v=spf1 mx -all"),
		rec("example.org", RecordKind::Mx, "10 mail.example.org"),
	]
}

fn config_in(dir: &Path, extra: &str) -> Config {
	toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = {dir:?}\ndomains = ['example.org']\n\
		 [dns]\nprovider = 'cloudflare'\nzone = 'example.org'\ntoken = 'inline-token'\n{extra}"
	))
	.expect("config")
}

fn harness_with(extra: &str) -> Harness {
	let dir = tempfile::tempdir().expect("directory");
	let config = config_in(dir.path(), extra);
	Harness { _dir: dir, config }
}

fn on() -> Harness {
	harness_with("[dns_publish]\nnull_records = true\nsenders = ['news.example.org']\n")
}

/// The same data directory with another configuration.
fn reconfigured(h: &Harness, extra: &str) -> Harness {
	Harness {
		_dir: tempfile::tempdir().expect("directory"),
		config: config_in(&h.config.data_dir, extra),
	}
}

fn run(h: &Harness, zone: &Zone) {
	let report = publish(h, zone, read(h, zone, &apex()));
	assert!(report.failure.is_none(), "{:?}", report.failure);
}

#[test]
fn a_run_publishes_the_null_records_at_every_depth_and_a_second_run_changes_nothing() {
	let h = on();
	let zone = Zone::with(vec![a("www.example.org"), a("x.y.z.example.org")]);
	run(&h, &zone);
	let now = zone.snapshot();
	for name in ["www.example.org", "x.y.z.example.org", "y.z.example.org"] {
		assert!(holds(&now, &spf_null(name)), "{name} null SPF");
		assert!(holds(&now, &mx_null(name)), "{name} null MX");
	}
	assert!(holds(&now, &spf_null("*.example.org")), "the wildcard");
	let ledger = store::load(&h.config.data_dir, "example.org").expect("ledger");
	assert!(ledger.owns(&spf_null("www.example.org")));
	let again = read(&h, &zone, &apex());
	assert!(!again.changes(), "a second run must change nothing");
}

#[test]
fn a_name_added_to_the_zone_later_is_covered_on_the_next_run() {
	let h = on();
	let zone = Zone::with(vec![a("www.example.org")]);
	run(&h, &zone);
	zone.records.lock().unwrap().push(a("blog.example.org"));
	run(&h, &zone);
	let now = zone.snapshot();
	assert!(holds(&now, &spf_null("blog.example.org")));
	assert!(holds(&now, &mx_null("blog.example.org")));
}

#[test]
fn a_name_that_becomes_a_sender_loses_only_what_epistle_published() {
	let h = on();
	let zone = Zone::with(vec![a("shop.example.org"), a("www.example.org")]);
	run(&h, &zone);
	assert!(holds(&zone.snapshot(), &spf_null("shop.example.org")));
	let later = reconfigured(
		&h,
		"[dns_publish]\nnull_records = true\nsenders = ['shop.example.org']\n",
	);
	run(&later, &zone);
	let now = zone.snapshot();
	assert!(!holds(&now, &spf_null("shop.example.org")));
	assert!(!holds(&now, &mx_null("shop.example.org")));
	assert!(holds(&now, &spf_null("www.example.org")), "the others stay");
}

#[test]
fn a_name_that_gets_an_spf_of_its_own_is_left_with_it_alone() {
	let h = on();
	let zone = Zone::with(vec![a("app.example.org")]);
	run(&h, &zone);
	let theirs = txt("app.example.org", "v=spf1 include:_spf.example.net -all");
	{
		let mut records = zone.records.lock().unwrap();
		records.retain(|r| !(r.name == "app.example.org" && r.value == "v=spf1 -all"));
		records.push(theirs.clone());
	}
	run(&h, &zone);
	let now = zone.snapshot();
	assert!(holds(&now, &theirs), "their SPF is never touched");
	assert!(!holds(&now, &mx_null("app.example.org")), "ours is retired");
}

#[test]
fn a_delegated_subdomain_is_left_intact() {
	let h = on();
	let zone = Zone::with(vec![
		a("www.example.org"),
		rec("sub.example.org", RecordKind::Ns, "ns.elsewhere.test"),
		a("host.sub.example.org"),
		a("x.y.sub.example.org"),
	]);
	let under = |records: &[DnsRecord]| -> Vec<String> {
		let mut lines: Vec<String> = records
			.iter()
			.filter(|r| r.name == "sub.example.org" || r.name.ends_with(".sub.example.org"))
			.map(|r| format!("{} {} {}", r.name, r.kind.as_str(), r.value))
			.collect();
		lines.sort();
		lines
	};
	let before = under(&zone.snapshot());
	run(&h, &zone);
	assert_eq!(under(&zone.snapshot()), before);
	assert!(holds(&zone.snapshot(), &spf_null("www.example.org")));
}

#[test]
fn without_the_option_nothing_is_published() {
	let h = harness_with("");
	let zone = Zone::with(vec![a("www.example.org")]);
	run(&h, &zone);
	assert!(!holds(&zone.snapshot(), &spf_null("www.example.org")));
}

#[test]
fn a_scoped_run_only_touches_its_domain() {
	let h = on();
	let zone = Zone::with(vec![a("www.example.org")]);
	let survey = read_scoped(&h, &zone, &apex(), Some("other.test")).expect("read");
	let report = publish(&h, &zone, survey);
	assert!(report.applied.is_empty());
	assert!(!holds(&zone.snapshot(), &spf_null("www.example.org")));
}
