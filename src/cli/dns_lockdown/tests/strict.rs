//! `epistle dns lockdown --strict-alignment`, from the command line to the
//! DMARC record that reaches the zone: `adkim=s` and `aspf=s` are published
//! with the flag and left out without it, an alignment the operator wrote is
//! replaced by the strict one, and the flag does not combine with `--undo`.

use std::process::ExitCode;

use clap::Parser;

use super::base::{CLOUDFLARE, Setup, run, setup, zone_records};
use crate::dns::lockdown::tests::support::{Zone, txt};
use crate::dns::provider::{DnsRecord, RecordKind};

fn dmarc(setup: &Setup) -> String {
	let records: Vec<DnsRecord> = setup
		.zone
		.snapshot()
		.into_iter()
		.filter(|record| {
			record.kind == RecordKind::Txt && record.name.starts_with("_dmarc.example.org")
		})
		.collect();
	assert_eq!(records.len(), 1, "one DMARC record: {records:?}");
	records[0].value.clone()
}

#[test]
fn the_flag_publishes_strict_alignment_and_without_it_the_tags_are_left_out() {
	let relaxed = setup(CLOUDFLARE, Zone::with(zone_records()));
	let published = run(&relaxed, &["--yes"]);
	assert_eq!(published.code, ExitCode::SUCCESS, "{}", published.err);
	let value = dmarc(&relaxed);
	assert!(
		!value.contains("adkim") && !value.contains("aspf"),
		"{value}"
	);

	let strict = setup(CLOUDFLARE, Zone::with(zone_records()));
	let published = run(&strict, &["--yes", "--strict-alignment"]);
	assert_eq!(published.code, ExitCode::SUCCESS, "{}", published.err);
	assert_eq!(
		dmarc(&strict),
		"v=DMARC1; p=quarantine; sp=quarantine; np=reject; adkim=s; aspf=s; rua=mailto:d@example.org"
	);
}

#[test]
fn a_dry_run_with_the_flag_shows_the_strict_record_and_publishes_nothing() {
	let setup = setup(CLOUDFLARE, Zone::with(zone_records()));
	let run = run(&setup, &["--dry-run", "--strict-alignment"]);
	assert_eq!(run.code, ExitCode::SUCCESS, "{}", run.err);
	assert!(run.out.contains("adkim=s; aspf=s"), "{}", run.out);
	assert_eq!(*setup.zone.writes.lock().unwrap(), 0);
}

#[test]
fn an_alignment_the_operator_wrote_is_replaced_and_other_tags_stay() {
	let mut records = zone_records();
	records.retain(|record| !record.name.starts_with("_dmarc"));
	records.push(txt(
		"_dmarc.example.org",
		"v=DMARC1; p=none; adkim=r; aspf=r; fo=1; rua=mailto:d@example.org",
	));
	let setup = setup(CLOUDFLARE, Zone::with(records));
	let published = run(&setup, &["--yes", "--strict-alignment"]);
	assert_eq!(published.code, ExitCode::SUCCESS, "{}", published.err);
	assert_eq!(
		dmarc(&setup),
		"v=DMARC1; p=quarantine; sp=quarantine; np=reject; adkim=s; aspf=s; fo=1; rua=mailto:d@example.org"
	);
}

#[test]
fn the_flag_does_not_combine_with_undo() {
	let error = crate::cli::Cli::try_parse_from([
		"epistle",
		"dns",
		"lockdown",
		"--undo",
		"--strict-alignment",
	])
	.expect_err("a conflict");
	assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
}
