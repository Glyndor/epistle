//! `epistle dns publish` end to end against a zone in memory: the
//! arguments, the plan on stdout, the confirmation, the ledger and
//! `--undo`. Nothing reaches a real DNS service.

use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;

use super::*;
use crate::dns::lockdown::tests::support::Zone;
use crate::dns::provider::{DnsRecord, RecordKind};

const CLOUDFLARE: &str = "\n[dns]\nprovider = 'cloudflare'\nzone = 'example.org'\ntoken_env = 'EPISTLE_TEST_UNSET_TOKEN'\n";

struct Setup {
	dir: tempfile::TempDir,
	file: tempfile::NamedTempFile,
	zone: Arc<Zone>,
}

struct Run {
	code: ExitCode,
	out: String,
	err: String,
}

fn setup(extra: &str, records: Vec<DnsRecord>) -> Setup {
	let (dir, file) = crate::cli::resource::test_config(extra);
	Setup {
		dir,
		file,
		zone: Arc::new(Zone::with(records)),
	}
}

fn parse(args: &[&str]) -> (PublishArgs, bool, bool) {
	let mut argv = vec!["epistle", "dns", "publish"];
	argv.extend_from_slice(args);
	let crate::cli::Command::Dns {
		action,
		dry_run,
		json,
		..
	} = crate::cli::Cli::try_parse_from(argv)
		.expect("arguments")
		.command
	else {
		unreachable!("dns arguments select the dns command")
	};
	let crate::cli::dns_provider::DnsCli::Publish(args) = action else {
		unreachable!("publish arguments select publish")
	};
	(args, dry_run, json)
}

fn run_with(setup: &Setup, args: &[&str], provider: Option<Arc<dyn DnsProvider>>) -> Run {
	let (args, dry_run, json) = parse(args);
	let deps = Deps {
		provider: &|_| Ok(provider.clone()),
		now: 1_800_000_000,
	};
	let mut out = Vec::new();
	let mut err = anstream::StripStream::new(Vec::new());
	let code = execute(
		setup.file.path(),
		&args,
		dry_run,
		json,
		&deps,
		&mut out,
		&mut err,
	);
	Run {
		code,
		out: String::from_utf8(out).expect("utf8"),
		err: String::from_utf8(err.into_inner()).expect("utf8"),
	}
}

fn run(setup: &Setup, args: &[&str]) -> Run {
	let provider: Arc<dyn DnsProvider> = setup.zone.clone();
	run_with(setup, args, Some(provider))
}

fn spf() -> DnsRecord {
	DnsRecord::new("example.org", RecordKind::Txt, "v=spf1 mx -all", 3600)
}

#[test]
fn a_dry_run_prints_the_plan_and_writes_nothing() {
	let setup = setup(CLOUDFLARE, vec![]);
	let run = run(&setup, &["--dry-run"]);
	assert_eq!(run.code, ExitCode::SUCCESS, "{}", run.err);
	assert!(run.out.contains("Zone example.org"), "{}", run.out);
	assert!(
		run.out
			.contains("create   example.org 3600 IN TXT \"v=spf1 mx -all\""),
		"{}",
		run.out
	);
	assert!(run.err.contains("dry run: nothing was published"));
	assert!(setup.zone.snapshot().is_empty());
	assert!(
		!setup
			.dir
			.path()
			.join("dns-publish")
			.join("example.org.json")
			.exists()
	);
}

#[test]
fn yes_publishes_and_a_second_run_has_nothing_to_change() {
	let setup = setup(CLOUDFLARE, vec![]);
	let first = run(&setup, &["--yes"]);
	assert_eq!(first.code, ExitCode::SUCCESS, "{}", first.err);
	assert!(
		setup
			.zone
			.snapshot()
			.iter()
			.any(|r| crate::dns::rrset::same_record(r, &spf()))
	);
	let second = run(&setup, &["--yes"]);
	assert_eq!(second.code, ExitCode::SUCCESS);
	assert!(second.err.contains("nothing to change"), "{}", second.err);
	assert!(second.out.contains("present"), "{}", second.out);
}

#[test]
fn json_prints_one_document_with_the_plan() {
	let setup = setup(CLOUDFLARE, vec![]);
	let run = run(&setup, &["--json", "--dry-run"]);
	assert_eq!(run.code, ExitCode::SUCCESS, "{}", run.err);
	let value: serde_json::Value = serde_json::from_str(&run.out).expect("one JSON document");
	assert_eq!(value["zones"][0]["zone"], "example.org");
	assert!(
		value["zones"][0]["entries"]
			.as_array()
			.expect("entries")
			.iter()
			.any(|e| e["action"] == "create")
	);
}

#[test]
fn without_a_provider_the_command_refuses_and_points_at_dns_records() {
	let setup = setup("", vec![]);
	let run = run_with(&setup, &["--yes"], None);
	assert_eq!(run.code, ExitCode::FAILURE);
	assert!(run.err.contains("dns-records"), "{}", run.err);
	assert!(run.out.is_empty());
}

#[test]
fn a_domain_this_server_does_not_host_is_refused_before_any_read() {
	let setup = setup(CLOUDFLARE, vec![]);
	let run = run(&setup, &["other.example", "--yes"]);
	assert_eq!(run.code, ExitCode::FAILURE);
	assert!(
		run.err.contains("not a domain this server hosts"),
		"{}",
		run.err
	);
	assert_eq!(*setup.zone.writes.lock().unwrap(), 0);
}

#[test]
fn undo_withdraws_what_publish_wrote() {
	let theirs = DnsRecord::new(
		"example.org",
		RecordKind::Txt,
		"google-site-verification=abc",
		3600,
	);
	let setup = setup(CLOUDFLARE, vec![theirs.clone()]);
	assert_eq!(run(&setup, &["--yes"]).code, ExitCode::SUCCESS);
	let undo = run(&setup, &["--undo", "--yes"]);
	assert_eq!(undo.code, ExitCode::SUCCESS, "{}", undo.err);
	assert_eq!(setup.zone.snapshot(), vec![theirs]);
}

#[test]
fn a_provider_without_a_precondition_is_named_in_the_plan_and_in_the_json() {
	let setup = setup(CLOUDFLARE, vec![]);
	let text = run(&setup, &["--dry-run"]);
	assert!(
		text.out.contains("takes no precondition on a write"),
		"{}",
		text.out
	);
	let json = run(&setup, &["--json", "--dry-run"]);
	let value: serde_json::Value = serde_json::from_str(&json.out).expect("one JSON document");
	assert_eq!(value["unguarded"], serde_json::json!(["example.org"]));
}

#[test]
fn a_provider_that_checks_a_precondition_carries_no_such_note() {
	let setup = setup(CLOUDFLARE, vec![]);
	let provider: Arc<dyn DnsProvider> =
		Arc::new(crate::dns::publish::FakeGuardedProvider::holding(vec![]));
	let text = run_with(&setup, &["--dry-run"], Some(provider.clone()));
	assert_eq!(text.code, ExitCode::SUCCESS, "{}", text.err);
	assert!(!text.out.contains("no precondition"), "{}", text.out);
	let json = run_with(&setup, &["--json", "--dry-run"], Some(provider));
	let value: serde_json::Value = serde_json::from_str(&json.out).expect("one JSON document");
	assert_eq!(value["unguarded"], serde_json::json!([]));
}

#[test]
fn undo_says_when_the_provider_could_only_remove_by_name() {
	let setup = setup(CLOUDFLARE, vec![]);
	assert_eq!(run(&setup, &["--yes"]).code, ExitCode::SUCCESS);
	let undo = run(&setup, &["--undo", "--yes"]);
	assert_eq!(undo.code, ExitCode::SUCCESS, "{}", undo.err);
	assert!(
		undo.err.contains("went without a precondition"),
		"{}",
		undo.err
	);
}
