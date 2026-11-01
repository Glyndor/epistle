//! `dkim split --finish`: retire the records of the shared key that are still
//! published at the domains that left it.
//!
//! Until they are gone, whoever holds the shared key can still sign as those
//! domains and receivers find a valid key. Nothing here removes a record it
//! has not shown to be the shared key's:
//!
//! - a record is the shared key's only when its `p=` is the public key of a key
//!   this host knows is the shared one; any other record at the name is
//!   reported as not ours and left alone;
//! - a lookup that fails, or a record with no `p=`, stops the command with a
//!   failure, because "could not read" is not "gone";
//! - the domain's own record must resolve with its own key before the old one
//!   goes;
//! - the overlap window runs from the moment `split` wrote the domain's entry
//!   (`dkim-split.json`), and a domain with no moment recorded is refused
//!   unless `--skip-overlap-check` says otherwise;
//! - the record is deleted with the exact value that was read, and only
//!   records at domains that have a `[[dkim.domain]]` entry are ever looked
//!   at, so the domain that kept the `[dkim]` key never loses its record.

use std::io::Write;
use std::process::ExitCode;

use super::{Options, Services, publish, switched};
use crate::cli::json_out::Report;
use crate::config::Config;
use crate::dkim::stale::{self, Stale};

/// A record of the shared key and the exact value that was read.
type Shared = (Stale, String);

/// The public keys of a domain's own records, by name, as its entry names them.
fn own_records(config: &Config, domain: &str) -> Result<Vec<(String, String)>, String> {
	let entry = config
		.dkim
		.as_ref()
		.and_then(|dkim| dkim.override_for(domain))
		.ok_or_else(|| format!("{domain} has no [[dkim.domain]] entry"))?;
	let mut found = Vec::new();
	let ed = crate::dkim::Signer::load(&entry.selector, &entry.key_file)
		.map_err(|error| format!("{} does not load: {error}", entry.key_file.display()))?;
	let p = stale::public_part(&ed.dns_record_value()).unwrap_or_default();
	found.push((format!("{}._domainkey.{domain}", entry.selector), p));
	if let (Some(selector), Some(file)) = (&entry.rsa_selector, &entry.rsa_key_file) {
		let record = crate::dkim::rsa_record_value(file)
			.map_err(|error| format!("{} does not load: {error}", file.display()))?;
		let p = stale::public_part(&record).unwrap_or_default();
		found.push((format!("{selector}._domainkey.{domain}"), p));
	}
	Ok(found)
}

/// The names of `domain`'s own records that a resolver does not show with the
/// right key, or why they could not be checked.
async fn own_missing(
	config: &Config,
	services: &Services<'_>,
	domain: &str,
) -> Result<Vec<String>, String> {
	let mut missing = Vec::new();
	for (name, p) in own_records(config, domain)? {
		let seen = match services.resolver.txt(&name).await {
			Ok(values) => values
				.iter()
				.any(|value| stale::public_part(value).as_deref() == Some(p.as_str())),
			Err(_) => return Err(format!("the lookup of {name} failed")),
		};
		if !seen {
			missing.push(name);
		}
	}
	Ok(missing)
}

fn fail(err: &mut impl Write, why: impl std::fmt::Display) -> ExitCode {
	crate::cli::style::error_to(err, format_args!("dkim split --finish refused: {why}"));
	ExitCode::FAILURE
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
		Err(reason) => return fail(err, reason),
	};
	let found = stale::survey(services.resolver, candidates).await;
	for (record, why) in &found.not_ours {
		report.line(format_args!(
			"not ours, left alone: {} ({why})",
			record.name
		));
	}
	if !found.unknown.is_empty() {
		let names: Vec<String> = found
			.unknown
			.iter()
			.map(|(record, why)| format!("{}: {why}", record.name))
			.collect();
		return fail(
			err,
			format_args!(
				"cannot tell whether the shared key is still published ({}); nothing was removed",
				names.join("; ")
			),
		);
	}
	let present: Vec<Shared> = found.shared;
	let not_ours: Vec<String> = found.not_ours.iter().map(|(r, _)| r.name.clone()).collect();
	if present.is_empty() {
		report.line(
			"nothing to retire: the shared key is not published at a domain with a key of its own",
		);
		return report.object(serde_json::json!({
			"result": "unchanged", "action": "split-finish",
			"stale_records": [], "not_ours": not_ours,
		}));
	}
	// The domain's own record must resolve with its own key before the old one goes.
	let mut domains: Vec<&str> = present.iter().map(|(r, _)| r.domain.as_str()).collect();
	domains.dedup();
	let mut problems = Vec::new();
	for domain in domains {
		match own_missing(config, services, domain).await {
			Ok(missing) => problems.extend(
				missing
					.into_iter()
					.map(|name| format!("{name} does not show the domain's own key")),
			),
			Err(why) => problems.push(why),
		}
	}
	if !problems.is_empty() {
		return fail(
			err,
			format_args!(
				"a domain's own record is not confirmed ({}); the shared key stays published",
				problems.join("; ")
			),
		);
	}
	// The overlap runs from the switch; no recorded switch fails closed.
	let moments = match switched::read(&config.data_dir) {
		Ok(moments) => moments,
		Err(why) => return fail(err, why),
	};
	let overlap = crate::dkim::ROTATE_OVERLAP_DAYS * 86_400;
	let mut held = Vec::new();
	for (record, _) in &present {
		match moments.get(&record.domain) {
			None => held.push(format!(
				"{}: no switch time recorded for {}",
				record.name, record.domain
			)),
			Some(at) if at.saturating_add(overlap) > now => held.push(format!(
				"{}: not before {}",
				record.name,
				crate::clock::rfc3339_or_epoch(at.saturating_add(overlap))
			)),
			Some(_) => {}
		}
	}
	let names: Vec<String> = present.iter().map(|(r, _)| r.name.clone()).collect();
	if options.dry_run {
		for (record, _) in &present {
			report.line(format_args!("would retire {}", record.name));
		}
		for line in &held {
			report.line(format_args!("held: {line}"));
		}
		return report.object(serde_json::json!({
			"result": "dry-run", "action": "split-finish",
			"stale_records": names, "held": held, "not_ours": not_ours,
		}));
	}
	if !held.is_empty() {
		if !options.skip_overlap_check {
			return fail(
				err,
				format_args!(
					"the overlap window is not confirmed ({}); --skip-overlap-check retires them anyway",
					held.join("; ")
				),
			);
		}
		crate::cli::style::warn_to(
			err,
			format_args!(
				"--skip-overlap-check: retiring without the overlap window ({}); mail signed before the switch may still be queued elsewhere",
				held.join("; ")
			),
		);
	}
	let zone = config.dns.as_ref().map(|dns| dns.zone.clone());
	let (automatic, manual): (Vec<&Shared>, Vec<&Shared>) =
		present.iter().partition(|(record, _)| {
			services.provider.is_some()
				&& zone
					.as_deref()
					.is_some_and(|zone| publish::in_zone(&record.name, zone))
		});
	if let (Some(provider), Some(zone)) = (&services.provider, &zone) {
		let targets: Vec<(String, String)> = automatic
			.iter()
			.map(|(record, value)| (record.name.clone(), value.clone()))
			.collect();
		let failed = publish::retire(provider.as_ref(), zone, &targets).await;
		if !failed.is_empty() {
			for line in &failed {
				crate::cli::style::error_to(err, format_args!("cannot remove {line}"));
			}
			return ExitCode::FAILURE;
		}
	}
	for (record, _) in &automatic {
		report.line(format_args!("retired TXT {}", record.name));
	}
	for (record, _) in &manual {
		report.line(format_args!("remove by hand: {}", record.name));
	}
	report.object(serde_json::json!({
		"result": "retired",
		"action": "split-finish",
		"retired": automatic.iter().map(|(r, _)| r.name.clone()).collect::<Vec<_>>(),
		"manual": manual.iter().map(|(r, _)| r.name.clone()).collect::<Vec<_>>(),
		"not_ours": not_ours,
	}))
}
