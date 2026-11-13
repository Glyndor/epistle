//! The keys a split moves domains to, and how the plan and the stale records are reported.

use std::path::Path;

use crate::cli::json_out::Report;
use crate::config::Config;
use crate::dkim::domain_keys::{self, DomainKeys};
use crate::dkim::stale::{self, Stale};

use super::{plan, publish};

/// The keys a domain moves to, with the records they are published as.
pub(super) struct Move {
	pub(super) domain: String,
	pub(super) keys: DomainKeys,
	pub(super) records: Vec<publish::Record>,
}

/// Make the keys of the domains that move, reusing the ones a run that
/// stopped left. A key that exists must load; one that does not is an error.
pub(super) fn make_keys(config: &Config, plan: &plan::Plan, now: u64) -> Result<Vec<Move>, String> {
	// A new key never takes a selector the shared key is published under:
	// the record would replace the one the server still signs with.
	let reserved = domain_keys::reserved_selectors(config)?;
	plan.moves
		.iter()
		.map(|domain| {
			let (keys, _) =
				domain_keys::ensure(&config.data_dir, domain, plan.dual_signing, now, &reserved)?;
			let records = publish::records(domain, &keys)?;
			Ok(Move {
				domain: domain.clone(),
				keys,
				records,
			})
		})
		.collect()
}

/// The keys a domain moves to, ed25519 first: the selector each is
/// published under and the file it is written to. A domain that signs with
/// two keys gets two, and the dry run says so.
pub(super) fn keys_of(keys: &DomainKeys) -> Vec<(&str, &Path)> {
	let mut all = vec![(keys.selector.as_str(), keys.key_file.as_path())];
	if let Some((selector, file)) = &keys.rsa {
		all.push((selector.as_str(), file.as_path()));
	}
	all
}

/// The plan as lines and as a JSON object.
pub(super) fn describe(plan: &plan::Plan, moves: &[(String, DomainKeys)]) -> serde_json::Value {
	serde_json::json!({
		"keeps": plan.keeps,
		"moves": moves.iter().map(|(domain, keys)| serde_json::json!({
			"domain": domain,
			"selector": keys.selector,
			"rsa_selector": keys.rsa.as_ref().map(|(selector, _)| selector),
			"key_file": keys.key_file,
		})).collect::<Vec<_>>(),
	})
}

/// The records of the shared key that are still published at the domains
/// in `moves`, with the grace the operator has before removing them.
pub(super) fn stale_of(
	config: &Config,
	moves: &[(String, DomainKeys)],
) -> Result<Vec<Stale>, String> {
	let mut all = Vec::new();
	for (domain, keys) in moves {
		let mut own = vec![keys.selector.clone()];
		own.extend(keys.rsa.iter().map(|(selector, _)| selector.clone()));
		all.extend(stale::names_for(config, domain, &own)?);
	}
	Ok(all)
}

/// Add the stale records to a result object and say them in the text report.
pub(super) fn report_stale(
	report: &mut Report<'_>,
	result: &mut serde_json::Value,
	stale: &[Stale],
) {
	for record in stale {
		report.line(format_args!(
			"stale after the switch: {} still publishes the shared key; retire it with `epistle dkim split --finish` once the overlap of {} days has passed",
			record.name,
			crate::dkim::ROTATE_OVERLAP_DAYS
		));
	}
	result["stale_records"] = stale
		.iter()
		.map(|record| record.name.clone())
		.collect::<Vec<_>>()
		.into();
}
