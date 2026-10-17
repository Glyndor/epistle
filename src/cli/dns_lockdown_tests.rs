//! Tests for `epistle dns lockdown` end to end: arguments, the exact
//! output, the confirmation, the journal file, `--undo`, and the path
//! without a provider. The provider is a zone in memory; nothing reaches
//! a real DNS service.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;

use super::lockdown_handler::{Deps, LockdownArgs, execute, render};
use crate::cli::status::dns_fake::FakeDns;
use crate::dns::lockdown::tests_support::{Zone, a, mx, rec, txt};
use crate::dns::lockdown::{Journal, Plan};
use crate::dns::provider::{DnsProvider, DnsRecord, RecordKind};
use crate::spf::DnsLookup;

const CLOUDFLARE: &str = "\n[dns]\nprovider = 'cloudflare'\nzone = 'example.org'\ntoken_env = 'EPISTLE_TEST_UNSET_TOKEN'\n";

/// 2026-10-14 12:00 UTC.
const NOW: u64 = 1_791_979_200;

struct Setup {
	_dir: tempfile::TempDir,
	file: tempfile::NamedTempFile,
	data_dir: PathBuf,
	zone: Arc<Zone>,
}

struct Run {
	code: ExitCode,
	out: String,
	err: String,
}

fn zone_records() -> Vec<DnsRecord> {
	vec![
		a("example.org"),
		mx("example.org", "10 mail.example.org"),
		txt("example.org", "v=spf1 mx -all"),
		a("mail.example.org"),
		a("www.example.org"),
		rec("blog.example.org", RecordKind::Cname, "blogs.example.net"),
		txt(
			"_dmarc.example.org",
			"v=DMARC1; p=none; rua=mailto:d@example.org",
		),
	]
}

fn setup(extra: &str, zone: Zone) -> Setup {
	let (dir, file) = crate::cli::resource::test_config(extra);
	let data_dir = dir.path().canonicalize().expect("data dir");
	Setup {
		_dir: dir,
		file,
		data_dir,
		zone: Arc::new(zone),
	}
}

fn parse(args: &[&str]) -> (LockdownArgs, bool) {
	let mut argv = vec!["epistle", "dns", "lockdown"];
	argv.extend_from_slice(args);
	let crate::cli::Command::Dns {
		action, dry_run, ..
	} = crate::cli::Cli::try_parse_from(argv)
		.expect("arguments")
		.command
	else {
		unreachable!("dns arguments select the dns command")
	};
	let super::DnsCli::Lockdown(args) = action else {
		unreachable!("lockdown arguments select lockdown")
	};
	(args, dry_run)
}

fn run_with(
	setup: &Setup,
	args: &[&str],
	provider: Option<Arc<dyn DnsProvider>>,
	dns: FakeDns,
) -> Run {
	let (args, dry_run) = parse(args);
	let dns = std::sync::Mutex::new(Some(dns));
	let deps = Deps {
		provider: &|_| Ok(provider.clone()),
		resolver: &|| {
			let dns = dns.lock().unwrap().take().expect("one resolver per run");
			Ok(Box::new(dns) as Box<dyn DnsLookup>)
		},
		now: NOW,
	};
	let mut out = Vec::new();
	let mut err = anstream::StripStream::new(Vec::new());
	let code = execute(setup.file.path(), &args, dry_run, &deps, &mut out, &mut err);
	Run {
		code,
		out: String::from_utf8(out).expect("utf8"),
		err: String::from_utf8(err.into_inner()).expect("utf8"),
	}
}

fn run(setup: &Setup, args: &[&str]) -> Run {
	let provider: Arc<dyn DnsProvider> = setup.zone.clone();
	run_with(setup, args, Some(provider), FakeDns::default())
}

fn journal_path(setup: &Setup) -> PathBuf {
	setup.data_dir.join("dns-lockdown").join("example.org.json")
}

fn journal(setup: &Setup) -> Journal {
	serde_json::from_str(&std::fs::read_to_string(journal_path(setup)).expect("journal"))
		.expect("json")
}

fn sorted(records: Vec<DnsRecord>) -> Vec<String> {
	let mut lines: Vec<String> = records
		.into_iter()
		.map(|r| format!("{} {} {}", r.name, r.kind.as_str(), r.value))
		.collect();
	lines.sort();
	lines
}

const PLAN: &str = r#"Lockdown plan for example.org

DMARC at _dmarc.example.org: p=none now; this run sets p=quarantine (sp=quarantine, np=reject); the next run moves it one more step, to p=reject
DMARC aggregate reports: none received for example.org in the last 30 days, so no sender can be checked before the policy changes.

Records to add or change:
  + _dmarc.example.org 3600 IN TXT "v=DMARC1; p=quarantine; sp=quarantine; np=reject; rua=mailto:d@example.org"
      reason: move _dmarc.example.org from p=none to p=quarantine; sp follows p; np=reject; the other tags stay as written; pct is dropped (DMARCbis)
      replaces: "v=DMARC1; p=none; rua=mailto:d@example.org"
  + www.example.org 3600 IN TXT "v=spf1 -all"
      reason: www.example.org has an address record and no SPF; v=spf1 -all says it sends no mail
  + www.example.org 3600 IN MX 0 .
      reason: www.example.org has an address record and no MX; MX 0 . (RFC 7505) says it accepts no mail
  + *.example.org 3600 IN TXT "v=spf1 -all"
      reason: the zone has no wildcard; *.example.org v=spf1 -all covers names that do not exist (a wildcard never applies to a name that has records of its own)

Left as is:
  = blog.example.org
      reason: blog.example.org is a CNAME, and no other record may sit next to a CNAME (RFC 1034 section 3.6.2); a null SPF and null MX belong at the name it points to; left as is
  = example.org
      reason: epistle serves example.org (a mail domain epistle hosts); left as is
  = mail.example.org
      reason: epistle serves mail.example.org (the mail hostname); left as is

Wildcard *.example.org: added; the zone has no wildcard; *.example.org v=spf1 -all covers names that do not exist (a wildcard never applies to a name that has records of its own)
"#;

#[test]
fn a_dry_run_prints_the_plan_and_publishes_nothing() {
	let setup = setup(CLOUDFLARE, Zone::with(zone_records()));
	let run = run(&setup, &["--dry-run"]);
	assert_eq!(run.code, ExitCode::SUCCESS);
	assert_eq!(run.out, PLAN);
	assert_eq!(run.err, "dry run: nothing was published\n");
	assert_eq!(*setup.zone.writes.lock().unwrap(), 0);
	assert!(!journal_path(&setup).exists());
}

#[test]
fn the_json_plan_is_the_text_plan() {
	let setup = setup(CLOUDFLARE, Zone::with(zone_records()));
	let json = run(&setup, &["--dry-run", "--json"]);
	assert_eq!(json.code, ExitCode::SUCCESS);
	let plan: Plan = serde_json::from_str(&json.out).expect("the output is one JSON plan");
	assert_eq!(render::plan_text(&plan), PLAN);
}

#[test]
fn without_yes_and_without_a_terminal_nothing_is_published() {
	let setup = setup(CLOUDFLARE, Zone::with(zone_records()));
	let run = run(&setup, &[]);
	assert_eq!(run.code, ExitCode::from(2));
	assert_eq!(run.out, PLAN);
	assert_eq!(*setup.zone.writes.lock().unwrap(), 0);
	assert!(!journal_path(&setup).exists());
}

#[test]
fn yes_publishes_and_a_second_run_has_nothing_to_change() {
	let setup = setup(CLOUDFLARE, Zone::with(zone_records()));
	let first = run(&setup, &["--yes", "--dmarc", "reject"]);
	assert_eq!(first.code, ExitCode::SUCCESS, "{}", first.err);
	assert_eq!(
		first.err,
		"published 4 records; `epistle dns lockdown --undo` removes them\n"
	);
	assert_eq!(journal(&setup).entries.len(), 4);
	let writes = *setup.zone.writes.lock().unwrap();
	let second = run(&setup, &["--yes"]);
	assert_eq!(second.code, ExitCode::SUCCESS);
	assert_eq!(second.err, "nothing to change\n");
	assert!(second.out.contains(
		"DMARC at _dmarc.example.org: already at p=reject with sp=reject and np=reject; nothing to change\n"
	));
	assert!(second.out.contains("Records to add or change:\n  (none)\n"));
	assert_eq!(*setup.zone.writes.lock().unwrap(), writes);
}

#[test]
fn undo_shows_what_it_will_do_then_puts_the_zone_back() {
	let setup = setup(CLOUDFLARE, Zone::with(zone_records()));
	assert_eq!(run(&setup, &["--yes"]).code, ExitCode::SUCCESS);
	let writes = *setup.zone.writes.lock().unwrap();
	let preview = run(&setup, &["--undo", "--dry-run"]);
	assert_eq!(preview.code, ExitCode::SUCCESS);
	assert_eq!(
		preview.out,
		concat!(
			"Undo lockdown for example.org (dry run)\n",
			"  - *.example.org 3600 IN TXT \"v=spf1 -all\": would be deleted\n",
			"  - www.example.org 3600 IN MX 0 .: would be deleted\n",
			"  - www.example.org 3600 IN TXT \"v=spf1 -all\": would be deleted\n",
			"  - TXT _dmarc.example.org: would be restored to \"v=DMARC1; p=none; rua=mailto:d@example.org\"\n",
		)
	);
	assert_eq!(preview.err, "dry run: nothing was changed\n");
	assert_eq!(*setup.zone.writes.lock().unwrap(), writes);
	let undo = run(&setup, &["--undo", "--yes"]);
	assert_eq!(undo.code, ExitCode::SUCCESS, "{}", undo.err);
	// A real run is not a dry run: the preview it asks about says so.
	assert_eq!(
		undo.out,
		concat!(
			"Undo lockdown for example.org\n",
			"  - *.example.org 3600 IN TXT \"v=spf1 -all\": will be deleted\n",
			"  - www.example.org 3600 IN MX 0 .: will be deleted\n",
			"  - www.example.org 3600 IN TXT \"v=spf1 -all\": will be deleted\n",
			"  - TXT _dmarc.example.org: will be restored to \"v=DMARC1; p=none; rua=mailto:d@example.org\"\n",
		)
	);
	assert_eq!(
		undo.err,
		"undone: 3 deleted, 1 restored, 0 left as is; journal removed\n"
	);
	assert_eq!(sorted(setup.zone.snapshot()), sorted(zone_records()));
	assert!(!journal_path(&setup).exists());
}

#[test]
fn undo_without_a_journal_has_nothing_to_do() {
	let setup = setup(CLOUDFLARE, Zone::with(zone_records()));
	let run = run(&setup, &["--undo", "--yes"]);
	assert_eq!(run.code, ExitCode::SUCCESS);
	assert_eq!(
		run.err,
		"no lockdown journal for example.org; nothing to undo\n"
	);
	assert_eq!(*setup.zone.writes.lock().unwrap(), 0);
}

#[test]
fn a_provider_failure_halfway_keeps_the_journal_on_disk() {
	let zone = Zone {
		fail_on: Some(3),
		..Zone::with(zone_records())
	};
	let setup = setup(CLOUDFLARE, zone);
	let run = run(&setup, &["--yes"]);
	assert_eq!(run.code, ExitCode::FAILURE);
	assert_eq!(
		run.err,
		concat!(
			"error: publishing MX www.example.org failed: provider error: rate limited\n",
			"the journal lists the 2 records that were published; `epistle dns lockdown --undo` removes them\n",
		)
	);
	let names: Vec<String> = journal(&setup)
		.entries
		.iter()
		.map(|e| format!("{} {}", e.record.kind.as_str(), e.record.name))
		.collect();
	assert_eq!(names, vec!["TXT _dmarc.example.org", "TXT www.example.org"]);
}

#[test]
fn an_unreadable_journal_stops_before_anything_is_read_or_written() {
	let setup = setup(CLOUDFLARE, Zone::with(zone_records()));
	std::fs::create_dir_all(journal_path(&setup).parent().unwrap()).unwrap();
	std::fs::write(journal_path(&setup), "{ not json").unwrap();
	let run = run(&setup, &["--yes"]);
	assert_eq!(run.code, ExitCode::FAILURE);
	assert!(
		run.err.starts_with(&format!(
			"error: the journal {} is not readable (",
			journal_path(&setup).display()
		)),
		"{}",
		run.err
	);
	assert!(
		run.err.ends_with("); move it aside to start over\n"),
		"{}",
		run.err
	);
	assert_eq!(*setup.zone.writes.lock().unwrap(), 0);
	assert_eq!(
		std::fs::read_to_string(journal_path(&setup)).unwrap(),
		"{ not json"
	);
}

#[test]
fn a_domain_must_be_valid_and_in_the_provider_zone() {
	let setup = setup(CLOUDFLARE, Zone::with(zone_records()));
	let outside = run(&setup, &["other.example", "--yes"]);
	assert_eq!(outside.code, ExitCode::FAILURE);
	assert_eq!(
		outside.err,
		"error: other.example is not in the example.org zone the [dns] provider manages\n"
	);
	let invalid = run(&setup, &["../example.org", "--yes"]);
	assert_eq!(invalid.code, ExitCode::FAILURE);
	assert_eq!(
		invalid.err,
		"error: ../example.org is not a valid domain name\n"
	);
	assert_eq!(*setup.zone.writes.lock().unwrap(), 0);
}

#[test]
fn failing_senders_in_the_reports_are_a_warning_before_the_step() {
	let setup = setup(CLOUDFLARE, Zone::with(zone_records()));
	let report = crate::reports::dmarc::DmarcReport {
		org_name: "receiver.example".into(),
		email: None,
		report_id: "r1".into(),
		date_range: crate::reports::dmarc::DateRange { begin: 0, end: 0 },
		policy_published: crate::reports::dmarc::PolicyPublished {
			domain: "example.org".into(),
			p: "none".into(),
			sp: None,
			pct: 100,
		},
		records: vec![crate::reports::dmarc::Row {
			source_ip: "198.51.100.7".into(),
			count: 12,
			disposition: "none".into(),
			dkim: "fail".into(),
			spf: "fail".into(),
			header_from: "example.org".into(),
		}],
		truncated: false,
	};
	crate::reports::dmarc::append(&setup.data_dir, "20261013", &report).expect("store report");
	let run = run(&setup, &["--dry-run"]);
	assert!(
		run.out.contains(concat!(
			"warning: these senders failed DMARC for example.org in the last 30 days; authorise each one that is yours (SPF or DKIM) before the policy gets stricter, or its mail will be quarantined or rejected:\n",
			"  - 198.51.100.7 (12 messages)\n",
		)),
		"{}",
		run.out
	);
}

#[test]
fn without_a_provider_the_plan_reads_the_live_dmarc_record() {
	let setup = setup("", Zone::default());
	let mut dns = FakeDns::default();
	dns.txt.insert(
		"_dmarc.example.org".into(),
		vec!["v=DMARC1; p=reject; sp=reject; np=reject".into()],
	);
	let run = run_with(&setup, &[], None, dns);
	assert_eq!(run.code, ExitCode::SUCCESS);
	assert!(run.out.contains(
		"DMARC at _dmarc.example.org: already at p=reject with sp=reject and np=reject; nothing to change\n"
	));
	assert!(
		run.out
			.contains("  + *.example.org 3600 IN TXT \"v=spf1 -all\"\n")
	);
	assert_eq!(
		run.err,
		"no DNS provider is configured: add the records above by hand. The null SPF and null MX for each name need the zone's record list, which only a configured provider can read.\n"
	);
	assert!(!journal_path(&setup).exists());
}

#[test]
fn the_flags_refuse_what_they_cannot_do() {
	let jump =
		crate::cli::Cli::try_parse_from(["epistle", "dns", "lockdown", "--dmarc", "quarantine"])
			.map(|_| ())
			.unwrap_err()
			.to_string();
	assert!(
		jump.contains("\"quarantine\" is not a DMARC jump; the only one is --dmarc reject"),
		"{jump}"
	);
	for args in [["--undo", "--json"], ["--undo", "--dmarc"]] {
		let mut argv = vec!["epistle", "dns", "lockdown"];
		argv.extend_from_slice(&args);
		if args[1] == "--dmarc" {
			argv.push("reject");
		}
		let error = crate::cli::Cli::try_parse_from(argv)
			.map(|_| ())
			.unwrap_err();
		assert_eq!(
			error.kind(),
			clap::error::ErrorKind::ArgumentConflict,
			"{args:?}"
		);
	}
}

#[test]
fn the_plan_shows_a_stricter_subdomain_policy_kept() {
	let mut records = zone_records();
	records.retain(|r| r.name != "_dmarc.example.org");
	records.push(txt("_dmarc.example.org", "v=DMARC1; p=none; sp=reject"));
	let setup = setup(CLOUDFLARE, Zone::with(records));
	let run = run(&setup, &["--dry-run"]);
	assert!(
		run.out.contains(
			"DMARC at _dmarc.example.org: p=none now; this run sets p=quarantine (sp=reject, np=reject); the next run moves it one more step, to p=reject\n"
		),
		"{}",
		run.out
	);
}

#[test]
fn a_unicode_domain_and_zone_names_are_compared_as_a_labels() {
	let setup = setup(CLOUDFLARE, Zone::with(vec![a("WWW.Bücher.example.org.")]));
	let run = run(&setup, &["Bücher.Example.org", "--dry-run"]);
	assert_eq!(run.code, ExitCode::SUCCESS, "{}", run.err);
	assert!(
		run.out
			.starts_with("Lockdown plan for xn--bcher-kva.example.org\n"),
		"{}",
		run.out
	);
	assert!(
		run.out
			.contains("  + www.xn--bcher-kva.example.org 3600 IN TXT \"v=spf1 -all\"\n  "),
		"{}",
		run.out
	);
}

#[test]
fn a_delegated_subdomain_is_reported_and_nothing_is_planned_under_it() {
	let mut records = zone_records();
	records.push(rec(
		"sub.example.org",
		RecordKind::Ns,
		"ns1.delegated.example.",
	));
	records.push(a("host.sub.example.org"));
	let setup = setup(CLOUDFLARE, Zone::with(records));
	let run = run(&setup, &["--dry-run"]);
	assert_eq!(run.code, ExitCode::SUCCESS, "{}", run.err);
	assert!(
		run.out.contains(
			"  = sub.example.org\n      reason: sub.example.org is delegated to other nameservers; left as is\n"
		),
		"{}",
		run.out
	);
	assert!(!run.out.contains("host.sub.example.org"), "{}", run.out);
	assert_eq!(*setup.zone.writes.lock().unwrap(), 0);
}

/// A zone is written by whoever has an account at the DNS provider, so a
/// name or a value in it can carry a terminal escape. Text output escapes
/// it; JSON output escapes it the way JSON does.
#[test]
fn control_characters_in_zone_text_never_reach_the_terminal() {
	let mut records = zone_records();
	records.push(a("evil\u{1b}[2J.example.org"));
	records.push(rec(
		"worse\u{7}.example.org",
		RecordKind::Ns,
		"ns\u{1b}]0;x\u{7}.",
	));
	let setup = setup(CLOUDFLARE, Zone::with(records));
	let text = run(&setup, &["--dry-run"]);
	assert_eq!(text.code, ExitCode::SUCCESS, "{}", text.err);
	assert!(
		text.out
			.contains("  + evil\\u{1b}[2j.example.org 3600 IN TXT \"v=spf1 -all\"\n"),
		"{}",
		text.out
	);
	assert!(
		text.out.contains(
			"  = worse\\u{7}.example.org\n      reason: worse\\u{7}.example.org is delegated"
		),
		"{}",
		text.out
	);
	let escapes = text
		.out
		.chars()
		.filter(|c| c.is_control() && *c != '\n')
		.count();
	assert_eq!(escapes, 0, "{}", text.out);
	let json = run(&setup, &["--dry-run", "--json"]);
	let raw = json
		.out
		.chars()
		.filter(|c| c.is_control() && *c != '\n')
		.count();
	assert_eq!(raw, 0, "{}", json.out);
}
