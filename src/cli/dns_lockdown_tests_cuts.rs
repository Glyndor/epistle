//! `epistle dns lockdown` against zones with delegations, text that is not
//! safe to print, and a provider that cannot list: what the operator reads,
//! and that nothing is written when the command cannot see the zone.

use std::process::ExitCode;
use std::sync::Arc;

use super::lockdown_tests::{CLOUDFLARE, journal_path, run, run_with, setup, zone_records};
use crate::cli::status::dns_fake::FakeDns;
use crate::dns::lockdown::tests_support::{Zone, a, rec};
use crate::dns::provider::{DnsProvider, DnsRecord, ProviderError, RecordKind};

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

/// A provider that cannot list a zone (Route 53, RFC 2136) leaves the
/// lockdown blind to delegations: it says so and writes nothing.
#[test]
fn a_provider_that_cannot_list_the_zone_stops_the_lockdown_before_any_write() {
	struct CannotList(std::sync::atomic::AtomicUsize);
	type Op<'a> = std::pin::Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>>;
	type ListOp<'a> =
		std::pin::Pin<Box<dyn Future<Output = Result<Vec<DnsRecord>, ProviderError>> + Send + 'a>>;
	impl DnsProvider for CannotList {
		fn upsert(&self, _zone: &str, _record: DnsRecord) -> Op<'_> {
			self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
			Box::pin(async { Ok(()) })
		}
		fn delete(&self, _zone: &str, _record: DnsRecord) -> Op<'_> {
			self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
			Box::pin(async { Ok(()) })
		}
		fn list(&self, _zone: &str) -> ListOp<'_> {
			Box::pin(async { Err(ProviderError::Unsupported) })
		}
	}
	let provider = Arc::new(CannotList(std::sync::atomic::AtomicUsize::new(0)));
	let setup = setup(CLOUDFLARE, Zone::default());
	let run = run_with(
		&setup,
		&["--yes"],
		Some(provider.clone()),
		FakeDns::default(),
	);
	assert_eq!(run.code, ExitCode::FAILURE);
	assert_eq!(run.out, "");
	assert_eq!(
		run.err,
		"error: this DNS provider cannot list the example.org zone, so the lockdown cannot see its delegations or its records; nothing was written\n"
	);
	assert_eq!(provider.0.load(std::sync::atomic::Ordering::SeqCst), 0);
	assert!(!journal_path(&setup).exists());
}
