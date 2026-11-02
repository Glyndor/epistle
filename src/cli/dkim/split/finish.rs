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
use crate::dkim::stale::{self, Found};

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
	let present: Vec<Found> = found.shared;
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
	let mut domains: Vec<&str> = present.iter().map(|f| f.stale.domain.as_str()).collect();
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
	for found in &present {
		let record = &found.stale;
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
	let names: Vec<String> = present.iter().map(|f| f.stale.name.clone()).collect();
	if options.dry_run {
		for found in &present {
			report.line(format_args!("would retire {}", found.stale.name));
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
	retire(config, services, &present, (&mut report, err), not_ours).await
}

/// The TXT record a provider is asked to remove.
fn txt(name: &str, value: &str) -> crate::dns::provider::DnsRecord {
	crate::dns::provider::DnsRecord {
		name: name.to_string(),
		kind: crate::dns::provider::RecordKind::Txt,
		value: value.to_string(),
		ttl: 300,
		proxied: None,
	}
}

/// Remove the shared key's values, one by one and by exact value, wherever the
/// provider can do that; list the rest for removal by hand. Then look again:
/// the shared key must be gone from every name that was handled, and every
/// record that is not ours must still be there.
async fn retire(
	config: &Config,
	services: &Services<'_>,
	present: &[Found],
	(report, err): (&mut Report<'_>, &mut impl Write),
	not_ours: Vec<String>,
) -> ExitCode {
	let zone = config.dns.as_ref().map(|dns| dns.zone.clone());
	let mut manual: Vec<(String, String)> = Vec::new();
	let mut handled: Vec<&Found> = Vec::new();
	let mut failures = Vec::new();
	for found in present {
		let name = &found.stale.name;
		let provider = services
			.provider
			.as_ref()
			.zip(zone.as_deref())
			.filter(|(_, zone)| publish::in_zone(name, zone));
		let Some((provider, zone)) = provider else {
			manual.extend(found.shared.iter().map(|v| (name.clone(), v.clone())));
			continue;
		};
		let mut all = true;
		for value in &found.shared {
			match provider.delete_exact(zone, txt(name, value)).await {
				Ok(()) => {}
				Err(crate::dns::provider::ProviderError::Unsupported) => {
					all = false;
					manual.push((name.clone(), value.clone()));
				}
				Err(error) => {
					all = false;
					failures.push(format!("{name}: {error}"));
				}
			}
		}
		if all {
			handled.push(found);
		}
	}
	if !failures.is_empty() {
		for line in &failures {
			crate::cli::style::error_to(err, format_args!("cannot remove {line}"));
		}
		return ExitCode::FAILURE;
	}
	if let Err(why) = verify(services, &handled).await {
		crate::cli::style::error_to(err, format_args!("dkim split --finish failed: {why}"));
		return ExitCode::FAILURE;
	}
	for found in &handled {
		report.line(format_args!("retired TXT {}", found.stale.name));
	}
	for (name, value) in &manual {
		report.line(format_args!("remove by hand: {name} {value}"));
	}
	let finished = manual.is_empty();
	if !finished {
		report.line(format_args!(
			"NOT finished: {} record(s) of the shared key are still published and must be removed by hand; `epistle dkim show` and `status` keep warning until they are gone",
			manual.len()
		));
	}
	let code = report.object(serde_json::json!({
		"result": if finished { "retired" } else { "manual-action-required" },
		"action": "split-finish",
		"retired": handled.iter().map(|f| f.stale.name.clone()).collect::<Vec<_>>(),
		"manual": manual
			.iter()
			.map(|(name, value)| serde_json::json!({ "name": name, "value": value }))
			.collect::<Vec<_>>(),
		"not_ours": not_ours,
	}));
	if finished || code != ExitCode::SUCCESS {
		code
	} else {
		ExitCode::from(MANUAL_ACTION)
	}
}

/// Exit code of `--finish` when records are left for the operator to remove by
/// hand: the command did what it could and the split is not finished.
pub(in crate::cli) const MANUAL_ACTION: u8 = 4;

/// After a removal: the shared key's `p=` is gone from every name in `handled`
/// (the resolver is asked again after each wait), and every value that was
/// not ours is still there.
async fn verify(services: &Services<'_>, handled: &[&Found]) -> Result<(), String> {
	let mut waits = services.waits.iter();
	loop {
		let candidates = handled.iter().map(|f| f.stale.clone()).collect();
		let after = stale::survey(services.resolver, candidates).await;
		let pending: Vec<&str> = after
			.shared
			.iter()
			.map(|f| f.stale.name.as_str())
			.chain(after.unknown.iter().map(|(r, _)| r.name.as_str()))
			.collect();
		if pending.is_empty() {
			break;
		}
		match waits.next() {
			Some(wait) => tokio::time::sleep(*wait).await,
			None => {
				return Err(format!(
					"the shared key is still visible, or could not be read, at {} after the removal",
					pending.join(", ")
				));
			}
		}
	}
	for found in handled {
		let now = services
			.resolver
			.txt(&found.stale.name)
			.await
			.map_err(|_| {
				format!(
					"the lookup of {} failed after the removal",
					found.stale.name
				)
			})?;
		for other in &found.others {
			if !now.contains(other) {
				return Err(format!(
					"a record that is not ours at {} is gone after the removal",
					found.stale.name
				));
			}
		}
	}
	Ok(())
}
