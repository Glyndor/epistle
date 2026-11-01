//! `dkim split --finish`: retire the records of the shared key that are still
//! published at the domains that left it.
//!
//! Until they are gone, whoever holds the shared key can still sign as those
//! domains and receivers find a valid key. They are removed only after the
//! overlap window, counted from the day each domain's own key was made, so mail
//! signed just before the switch and still in a remote queue verifies. Only
//! records at domains that have a `[[dkim.domain]]` entry are ever listed, so
//! the record of the domain that keeps the `[dkim]` key is never touched.

use std::io::Write;
use std::process::ExitCode;

use super::{Options, Services, publish};
use crate::cli::json_out::Report;
use crate::config::Config;
use crate::dkim::stale::{self, Stale};

/// Epoch second at which the overlap for `domain` has passed: its own key's
/// age plus [`crate::dkim::ROTATE_OVERLAP_DAYS`]. `None` when the key file
/// cannot be read, which refuses nothing and delays nothing.
fn not_before(config: &Config, domain: &str) -> Option<u64> {
	let entry = config.dkim.as_ref()?.override_for(domain)?;
	let modified = std::fs::metadata(&entry.key_file).ok()?.modified().ok()?;
	let made = modified
		.duration_since(std::time::UNIX_EPOCH)
		.ok()?
		.as_secs();
	Some(made + crate::dkim::ROTATE_OVERLAP_DAYS * 86_400)
}

/// Run the follow-up step.
pub(super) async fn finish(
	config: &Config,
	options: &Options,
	services: &Services<'_>,
	(json, out, err): (bool, &mut impl Write, &mut impl Write),
	now: u64,
) -> ExitCode {
	let mut report = Report::new(out, json);
	let candidates = match stale::names(config) {
		Ok(candidates) => candidates,
		Err(reason) => {
			crate::cli::style::error_to(err, format_args!("dkim split --finish refused: {reason}"));
			return ExitCode::FAILURE;
		}
	};
	let present = stale::published(services.resolver, candidates).await;
	if present.is_empty() {
		report.line(
			"nothing to retire: no record of the shared key is published at a domain with a key of its own",
		);
		return report.object(
			serde_json::json!({ "result": "unchanged", "action": "split-finish", "stale_records": [] }),
		);
	}
	let waiting: Vec<(&Stale, u64)> = present
		.iter()
		.filter_map(|record| Some((record, not_before(config, &record.domain)?)))
		.filter(|(_, at)| *at > now)
		.collect();
	let names: Vec<String> = present.iter().map(|r| r.name.clone()).collect();
	if options.dry_run || !waiting.is_empty() {
		for record in &present {
			let when = waiting
				.iter()
				.find(|(w, _)| w.name == record.name)
				.map(|(_, at)| format!(" (not before {})", crate::clock::rfc3339_or_epoch(*at)))
				.unwrap_or_default();
			report.line(format_args!("would retire {}{when}", record.name));
		}
		let held = !waiting.is_empty() && !options.dry_run;
		if held {
			crate::cli::style::error_to(
				err,
				"dkim split --finish refused: the overlap window has not passed for every domain",
			);
		}
		let _ = report.object(serde_json::json!({
			"result": if options.dry_run { "dry-run" } else { "waiting" },
			"action": "split-finish",
			"stale_records": names,
			"not_before": waiting.iter().map(|(r, at)| serde_json::json!({ "name": r.name, "at": at })).collect::<Vec<_>>(),
		}));
		return if held {
			ExitCode::FAILURE
		} else {
			ExitCode::SUCCESS
		};
	}
	let zone = config.dns.as_ref().map(|dns| dns.zone.clone());
	let (automatic, manual): (Vec<&Stale>, Vec<&Stale>) = present.iter().partition(|record| {
		services.provider.is_some()
			&& zone
				.as_deref()
				.is_some_and(|zone| publish::in_zone(&record.name, zone))
	});
	if let (Some(provider), Some(zone)) = (&services.provider, &zone) {
		let targets: Vec<String> = automatic.iter().map(|r| r.name.clone()).collect();
		let failed = publish::retire(provider.as_ref(), zone, &targets).await;
		if !failed.is_empty() {
			for line in &failed {
				crate::cli::style::error_to(err, format_args!("cannot remove {line}"));
			}
			return ExitCode::FAILURE;
		}
	}
	for record in &automatic {
		report.line(format_args!("retired TXT {}", record.name));
	}
	for record in &manual {
		report.line(format_args!("remove by hand: {}", record.name));
	}
	report.object(serde_json::json!({
		"result": "retired",
		"action": "split-finish",
		"retired": automatic.iter().map(|r| r.name.clone()).collect::<Vec<_>>(),
		"manual": manual.iter().map(|r| r.name.clone()).collect::<Vec<_>>(),
	}))
}
