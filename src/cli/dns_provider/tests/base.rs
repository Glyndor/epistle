use std::path::PathBuf;
use std::time::Duration;

use clap::{CommandFactory, Parser};

use super::*;
use crate::cli::resource::test_config;
use crate::dns::provider::{DnsProvider, DnsRecord, ProviderError, RecordKind};

type Op<'a> =
	std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ProviderError>> + Send + 'a>>;
type ListOp<'a> = std::pin::Pin<
	Box<dyn std::future::Future<Output = Result<Vec<DnsRecord>, ProviderError>> + Send + 'a>,
>;

pub(in super::super) const DNS: &str = "
# dns
[dns] # provider
provider = 'cloudflare' # who
zone = 'example.org'
token_env = 'CF_TOKEN' # secret source
";

pub(in super::super) fn no_restart(_: &Config, _: StackAction) -> ExitCode {
	panic!("a test host has no compose file, so nothing may be restarted")
}

pub(in super::super) struct Run {
	pub result: Result<ExitCode, super::super::super::resource::ResourceError>,
	pub out: String,
	pub status: String,
	pub before: String,
	pub after: String,
}

pub(in super::super) fn run(extra: &str, args: &[&str], dry_run: bool) -> Run {
	let (_dir, file) = test_config(extra);
	let before = std::fs::read_to_string(file.path()).unwrap();
	let mut full = vec!["epistle", "dns", "provider"];
	full.extend_from_slice(args);
	let crate::cli::Command::Dns { action, .. } =
		crate::cli::Cli::try_parse_from(full).unwrap().command
	else {
		unreachable!("dns arguments must select the dns command")
	};
	let (mut out, mut status) = (Vec::new(), Vec::new());
	let result = execute_with(
		file.path(),
		action,
		dry_run,
		false,
		&mut out,
		&mut status,
		no_restart,
	);
	Run {
		result,
		out: String::from_utf8(out).unwrap(),
		status: String::from_utf8(status).unwrap(),
		after: std::fs::read_to_string(file.path()).unwrap(),
		before,
	}
}

#[test]
fn dns_accepts_config_before_or_after_the_action_and_defaults_it() {
	let matches = crate::cli::Cli::command()
		.try_get_matches_from(["epistle", "dns", "provider", "show"])
		.unwrap();
	assert_eq!(
		matches
			.subcommand_matches("dns")
			.unwrap()
			.get_one::<PathBuf>("config")
			.unwrap(),
		&PathBuf::from("/etc/epistle/mail.toml")
	);
	let matches = crate::cli::Cli::command()
		.try_get_matches_from([
			"epistle",
			"dns",
			"provider",
			"show",
			"--config",
			"/tmp/x.toml",
		])
		.unwrap();
	assert_eq!(
		matches
			.subcommand_matches("dns")
			.unwrap()
			.get_one::<PathBuf>("config")
			.unwrap(),
		&PathBuf::from("/tmp/x.toml")
	);
}

#[test]
fn show_prints_sources_not_secrets() {
	let inline = "\n[dns]\nprovider = 'godaddy'\nzone = 'example.org'\naccess_key = 'key-id'\nsecret_key = 'hunter2-secret'\ntoken = 'tok-secret'\n";
	let run = run(inline, &["show"], false);
	assert_eq!(run.result.unwrap(), ExitCode::SUCCESS);
	assert_eq!(
		run.out,
		"provider\tgodaddy\nzone\texample.org\ntoken\tset\naccess_key\tkey-id\nsecret_key\tset\n"
	);
	assert!(!run.out.contains("hunter2") && !run.out.contains("tok-secret"));
	let run = super::base::run(DNS, &["show", "--json"], false);
	assert_eq!(
		run.out,
		"{\"provider\":\"cloudflare\",\"token_env\":\"CF_TOKEN\",\"zone\":\"example.org\"}\n"
	);
}

#[test]
fn show_without_a_provider_says_unset() {
	let run = run("", &["show"], false);
	assert_eq!(run.out, "provider\tunset\n");
	let run = super::base::run("", &["show", "--json"], false);
	assert_eq!(run.out, "null\n");
}

#[test]
fn unset_removes_the_section_and_keeps_its_comments() {
	let run = run(DNS, &["unset"], false);
	assert_eq!(run.result.unwrap(), ExitCode::SUCCESS);
	assert_eq!(
		run.after,
		run.before.replace(
			"\n# dns\n[dns] # provider\nprovider = 'cloudflare' # who\nzone = 'example.org'\ntoken_env = 'CF_TOKEN' # secret source\n",
			""
		) + "# dns\n# provider\n# who\n# secret source\n"
	);
	assert_eq!(
		run.status,
		"dns provider saved\nThe server must be restarted.\n"
	);
	let again = super::base::run("", &["unset"], false);
	assert_eq!(
		again.after, again.before,
		"unsetting nothing must change nothing"
	);
	assert_eq!(again.status, "dns provider unchanged\n");
}

#[test]
fn unset_dry_run_prints_the_diff_and_writes_nothing() {
	let run = run(DNS, &["unset"], true);
	assert!(run.out.contains("-zone = 'example.org'"), "{}", run.out);
	assert_eq!(run.after, run.before);
	assert!(run.status.is_empty());
}

struct Fake(Result<Vec<DnsRecord>, ProviderError>, bool);

impl DnsProvider for Fake {
	fn upsert(&self, _: &str, _: DnsRecord) -> Op<'_> {
		panic!("the test must never write")
	}
	fn delete(&self, _: &str, _: DnsRecord) -> Op<'_> {
		panic!("the test must never write")
	}
	fn list(&self, _: &str) -> ListOp<'_> {
		let (result, hang) = (self.0.clone(), self.1);
		Box::pin(async move {
			if hang {
				std::future::pending::<()>().await;
			}
			result
		})
	}
}

fn probe(
	provider: &Fake,
	limit: Duration,
) -> (
	Result<ExitCode, super::super::super::resource::ResourceError>,
	String,
	String,
) {
	let (mut out, mut status) = (Vec::new(), Vec::new());
	let result = probe::run_with("example.org", provider, limit, &mut out, &mut status);
	(
		result,
		String::from_utf8(out).unwrap(),
		String::from_utf8(status).unwrap(),
	)
}

#[test]
fn test_reports_the_record_count_and_writes_nothing() {
	let record = DnsRecord {
		name: "example.org".into(),
		kind: RecordKind::A,
		value: "192.0.2.1".into(),
		ttl: 300,
		proxied: None,
	};
	let (result, out, status) = probe(&Fake(Ok(vec![record]), false), Duration::from_secs(1));
	assert_eq!(result.unwrap(), ExitCode::SUCCESS);
	assert_eq!(out, "ok\t1 records in example.org\n");
	assert_eq!(status, "dns provider test passed; nothing was changed\n");
}

#[test]
fn test_reports_provider_failures_and_timeouts() {
	let (result, ..) = probe(
		&Fake(Err(ProviderError::Auth), false),
		Duration::from_secs(1),
	);
	assert_eq!(
		result.unwrap_err().as_ref(),
		"dns provider test failed for example.org: provider authentication failed"
	);
	let started = std::time::Instant::now();
	let (result, ..) = probe(&Fake(Ok(vec![]), true), Duration::from_millis(200));
	assert!(
		started.elapsed() < Duration::from_secs(5),
		"the limit must cut a provider that never answers"
	);
	assert_eq!(
		result.unwrap_err().as_ref(),
		"dns provider test failed for example.org: no answer within 0.2 s"
	);
}

#[test]
fn test_refuses_missing_manual_and_unresolvable_providers() {
	for (extra, message) in [
		(
			"",
			"no DNS provider is configured; run `epistle dns provider set` first",
		),
		(
			"\n[dns]\nprovider = 'manual'\nzone = 'example.org'\n",
			"the manual provider has no API to test",
		),
		(
			"\n[dns]\nprovider = 'cloudflare'\nzone = 'example.org'\ntoken_env = 'EPISTLE_TEST_UNSET_TOKEN'\n",
			"the provider credentials could not be resolved: check that the environment variable or file is available to the service account",
		),
	] {
		let run = run(extra, &["test"], false);
		assert_eq!(run.result.unwrap_err().as_ref(), message);
		assert_eq!(run.after, run.before);
	}
}
