//! `epistle dkim split`: give every domain that signs with the `[dkim]` key a
//! key of its own, without breaking the signature of any of them.
//!
//! One domain keeps the `[dkim]` key. For each of the others the command makes
//! a key under `keys/dkim/<domain>/`, publishes its record under a selector the
//! `[dkim]` key does not use, waits until a resolver shows the record, and only
//! then writes the domain's `[[dkim.domain]]` entry and restarts the server.
//! Until that restart the domain keeps signing with the key it signs with now,
//! whose record is not touched, so there is no moment at which a message is
//! signed with a key receivers cannot find. A run that stops anywhere before
//! the entry is written changes nothing about signing; running it again reuses
//! the keys and publishes the same records.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use crate::cli::config_edit::ConfigDocument;
use crate::cli::domain::own_key::add_entry;
use crate::cli::json_out::Report;
use crate::cli::resource::ResourceError;
use crate::config::Config;
use crate::dkim::domain_keys::{self, DomainKeys};
use crate::dkim::split_state;
use crate::dkim::stale::{self, Stale};
use crate::dns::provider::DnsProvider;
use crate::spf::DnsLookup;

mod finish;
mod plan;
mod publish;

/// How the command is asked to run.
pub(super) struct Options {
	/// Print the plan and change nothing.
	pub dry_run: bool,
	/// Seconds to wait for the new records to show in DNS.
	pub wait: u64,
	/// Retire the shared key's records at the domains that left it.
	pub finish: bool,
	/// With `finish`: retire even when the overlap window is not confirmed.
	pub skip_overlap_check: bool,
	/// Record that the server was restarted by hand onto the moved keys.
	pub restarted: bool,
}

/// What the command talks to besides the file system, so a test can supply
/// its own.
pub(super) struct Services<'a> {
	/// The provider that publishes the records, when `[dns]` builds one.
	pub provider: Option<Arc<dyn DnsProvider>>,
	/// The resolver that must show the records before signing switches.
	pub resolver: &'a dyn DnsLookup,
	/// The pauses between the queries that look for the records.
	pub waits: Vec<Duration>,
}

/// How long a run waits for another one on the same data directory.
const LOCK_WAIT: Duration = if cfg!(test) {
	Duration::from_millis(300)
} else {
	Duration::from_secs(30)
};

/// The seconds between queries while waiting for the records.
const POLL_SECONDS: u64 = 5;

/// Run `dkim split` against the configuration at `path`.
pub(super) fn run(path: &Path, options: &Options, json: bool, out: &mut impl Write) -> ExitCode {
	let config = match Config::load(path) {
		Ok(config) => config,
		Err(error) => {
			crate::cli::style::error(error);
			return ExitCode::FAILURE;
		}
	};
	let resolver = match crate::spf::SystemDns::uncached_from_system() {
		Ok(resolver) => resolver,
		Err(error) => {
			crate::cli::style::error(format_args!("cannot start resolver: {error}"));
			return ExitCode::FAILURE;
		}
	};
	let runtime = match tokio::runtime::Runtime::new() {
		Ok(runtime) => runtime,
		Err(error) => {
			crate::cli::style::error(format_args!("cannot start async runtime: {error}"));
			return ExitCode::FAILURE;
		}
	};
	let services = Services {
		provider: config
			.dns
			.as_ref()
			.and_then(|dns| dns.build_for_host(&config.hostname)),
		resolver: &resolver,
		waits: vec![Duration::from_secs(POLL_SECONDS); (options.wait / POLL_SECONDS) as usize],
	};
	let mut err = crate::cli::style::stderr();
	runtime.block_on(split(
		path,
		&config,
		options,
		&services,
		(json, out, &mut err),
		crate::cli::stack::run,
	))
}

/// The keys a domain moves to, with the records they are published as.
struct Move {
	domain: String,
	keys: DomainKeys,
	records: Vec<publish::Record>,
}

/// Make the keys of the domains that move, reusing the ones a run that
/// stopped left. A key that exists must load; one that does not is an error.
fn make_keys(config: &Config, plan: &plan::Plan, now: u64) -> Result<Vec<Move>, String> {
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

/// The plan as lines and as a JSON object.
fn describe(plan: &plan::Plan, moves: &[(String, DomainKeys)]) -> serde_json::Value {
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
fn stale_of(config: &Config, moves: &[(String, DomainKeys)]) -> Result<Vec<Stale>, String> {
	let mut all = Vec::new();
	for (domain, keys) in moves {
		let mut own = vec![keys.selector.clone()];
		own.extend(keys.rsa.iter().map(|(selector, _)| selector.clone()));
		all.extend(stale::names_for(config, domain, &own)?);
	}
	Ok(all)
}

/// Add the stale records to a result object and say them in the text report.
fn report_stale(report: &mut Report<'_>, result: &mut serde_json::Value, stale: &[Stale]) {
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

/// The command, with its services supplied.
pub(super) async fn split(
	path: &Path,
	config: &Config,
	options: &Options,
	services: &Services<'_>,
	(json, out, err): (bool, &mut impl Write, &mut impl Write),
	restart: impl FnOnce(&Config, crate::cli::stack::StackAction) -> ExitCode,
) -> ExitCode {
	let now = super::now_epoch();
	// One run at a time on a data directory: two that both found a key
	// missing, or both published, could end with DNS showing a key the
	// configuration does not name.
	let _held = if options.dry_run {
		None
	} else {
		match split_state::lock(&config.data_dir, LOCK_WAIT) {
			Ok(held) => Some(held),
			Err(why) => {
				crate::cli::style::error_to(err, format_args!("dkim split refused: {why}"));
				return ExitCode::FAILURE;
			}
		}
	};
	if options.restarted {
		return confirm_restart(config, (json, out, err));
	}
	if options.finish {
		return finish::finish(config, options, services, (json, out, err), now).await;
	}
	let plan = match plan::build(config) {
		Ok(Some(plan)) => plan,
		Ok(None) => return nothing_to_split(config, (json, out, err), restart),
		Err(reason) => {
			crate::cli::style::error_to(err, format_args!("dkim split refused: {reason}"));
			return ExitCode::FAILURE;
		}
	};
	let planned = |plan: &plan::Plan| -> Result<Vec<(String, DomainKeys)>, String> {
		let reserved = domain_keys::reserved_selectors(config)?;
		plan.moves
			.iter()
			.map(|domain| {
				domain_keys::planned(&config.data_dir, domain, plan.dual_signing, now, &reserved)
					.map(|keys| (domain.clone(), keys))
			})
			.collect()
	};
	if options.dry_run {
		let shown = match planned(&plan) {
			Ok(shown) => shown,
			Err(reason) => {
				crate::cli::style::error_to(err, format_args!("dkim split refused: {reason}"));
				return ExitCode::FAILURE;
			}
		};
		let mut report = Report::new(out, json);
		report.line(format_args!("keep {} on the [dkim] key", plan.keeps));
		for (domain, keys) in &shown {
			report.line(format_args!(
				"give {domain} a key of its own ({}) at {}",
				keys.selector,
				keys.key_file.display()
			));
			report.line(format_args!(
				"publish TXT {}._domainkey.{domain}, wait until it resolves, then switch signing",
				keys.selector
			));
		}
		let stale = stale_of(config, &shown).unwrap_or_default();
		let mut result = describe(&plan, &shown);
		report_stale(&mut report, &mut result, &stale);
		report.line("dry run: nothing changed");
		result["result"] = "dry-run".into();
		result["action"] = "split".into();
		return report.object(result);
	}
	let moves = match make_keys(config, &plan, now) {
		Ok(moves) => moves,
		Err(reason) => {
			crate::cli::style::error_to(err, format_args!("dkim split refused: {reason}"));
			return ExitCode::FAILURE;
		}
	};
	let records: Vec<publish::Record> = moves.iter().flat_map(|m| m.records.clone()).collect();
	let mut report = Report::new(out, json);
	// Publish what the provider can reach; print the rest for the operator.
	let zone = config.dns.as_ref().map(|dns| dns.zone.clone());
	let (automatic, manual): (Vec<_>, Vec<_>) = records.iter().cloned().partition(|record| {
		services.provider.is_some()
			&& zone
				.as_deref()
				.is_some_and(|zone| publish::in_zone(&record.name, zone))
	});
	if let (Some(provider), Some(zone)) = (&services.provider, &zone) {
		let failed = publish::publish(provider.as_ref(), zone, &automatic).await;
		if !failed.is_empty() {
			for line in &failed {
				crate::cli::style::error_to(err, format_args!("cannot publish {line}"));
			}
			crate::cli::style::error_to(
				err,
				"dkim split stopped before switching any domain; run it again once the provider accepts the records",
			);
			return ExitCode::FAILURE;
		}
	}
	for record in &automatic {
		report.line(format_args!("published TXT {}", record.name));
	}
	for record in &manual {
		report.line(format_args!(
			"publish by hand: {} 300 IN TXT {}",
			record.name,
			crate::dns::records::txt_zone_form(&record.value)
		));
	}
	let absent = publish::missing(services.resolver, &records, &services.waits).await;
	if !absent.is_empty() {
		for record in &absent {
			report.line(format_args!("not visible yet: {}", record.name));
		}
		report.line(
			"no domain was switched; run `epistle dkim split` again when the records resolve (the keys are kept)",
		);
		let shown: Vec<_> = moves
			.iter()
			.map(|m| (m.domain.clone(), m.keys.clone()))
			.collect();
		let stale = stale_of(config, &shown).unwrap_or_default();
		let mut result = describe(&plan, &shown);
		result["stale_records"] = stale
			.iter()
			.map(|r| r.name.clone())
			.collect::<Vec<_>>()
			.into();
		result["result"] = "waiting".into();
		result["action"] = "split".into();
		result["missing"] = absent
			.iter()
			.map(|r| r.name.clone())
			.collect::<Vec<_>>()
			.into();
		let _ = report.object(result);
		return ExitCode::FAILURE;
	}
	let shown: Vec<_> = moves
		.iter()
		.map(|m| (m.domain.clone(), m.keys.clone()))
		.collect();
	let stale = match stale_of(config, &shown) {
		Ok(stale) => stale,
		Err(reason) => {
			crate::cli::style::error_to(err, format_args!("dkim split refused: {reason}"));
			return ExitCode::FAILURE;
		}
	};
	switch(
		path,
		config,
		(&plan, &moves, &stale),
		&mut report,
		err,
		restart,
	)
}

/// `split` found nothing to move. If an earlier run wrote its entries and the
/// server was never restarted onto them, the restart is repeated: the keys on
/// disk are not the ones that sign until it happens.
fn nothing_to_split(
	config: &Config,
	(json, out, err): (bool, &mut impl Write, &mut impl Write),
	restart: impl FnOnce(&Config, crate::cli::stack::StackAction) -> ExitCode,
) -> ExitCode {
	let mut report = Report::new(out, json);
	let pending = match split_state::pending(&config.data_dir) {
		Ok(pending) => pending,
		Err(why) => {
			crate::cli::style::error_to(err, format_args!("dkim split refused: {why}"));
			return ExitCode::FAILURE;
		}
	};
	if pending.is_empty() {
		report.line("nothing to split: every hosted domain has a key of its own");
		return report.object(serde_json::json!({ "result": "unchanged", "action": "split" }));
	}
	report.line(format_args!(
		"{} signs with the shared key until the server is restarted onto its own: restarting now",
		pending.join(", ")
	));
	let (confirmed, reload) = match restart_onto(
		config,
		crate::cli::config_edit::Outcome::Changed,
		err,
		restart,
	) {
		Ok(done) => done,
		Err(code) => return code,
	};
	let pending_code = (!confirmed).then(|| restart_pending(&mut report));
	if confirmed {
		report.line("the server was restarted onto the moved keys");
	}
	let code = report.object(serde_json::json!({
		"result": if confirmed { "restarted" } else { "restart-pending" },
		"action": "split",
		"domains": pending,
		"reload": reload.name(),
	}));
	match pending_code {
		Some(pending) if code == ExitCode::SUCCESS => pending,
		_ => code,
	}
}

/// Restart the server and, when that is confirmed, record that the moved keys
/// are the ones signing. `Ok((confirmed, reload))`; `Err` carries the exit code
/// of a restart that failed.
fn restart_onto(
	config: &Config,
	outcome: crate::cli::config_edit::Outcome,
	err: &mut impl Write,
	restart: impl FnOnce(&Config, crate::cli::stack::StackAction) -> ExitCode,
) -> Result<(bool, crate::cli::json_out::Reload), ExitCode> {
	let reload = match crate::cli::config_edit::after_change_reporting(
		config, outcome, true, err, restart,
	) {
		Ok((ExitCode::SUCCESS, reload)) => reload,
		Ok((code, _)) => return Err(code),
		Err(ResourceError::Refusal(message) | ResourceError::Failure(message)) => {
			crate::cli::style::error_to(err, message);
			return Err(ExitCode::FAILURE);
		}
	};
	let confirmed = reload == crate::cli::json_out::Reload::Restarted;
	if confirmed && let Err(why) = split_state::mark_restarted(&config.data_dir, super::now_epoch())
	{
		crate::cli::style::error_to(err, format_args!("{why}"));
		return Err(ExitCode::FAILURE);
	}
	Ok((confirmed, reload))
}

/// What to say, and the exit code, when the server is not confirmed to run the
/// moved keys: 4, the code of a split that still needs the operator.
fn restart_pending(report: &mut Report<'_>) -> ExitCode {
	report.line(
		"the server is NOT confirmed to run the moved keys: restart it, then run `epistle dkim split --restarted` (or `epistle dkim split` again, which restarts it if it can)",
	);
	ExitCode::from(finish::MANUAL_ACTION)
}

/// `--restarted`: the operator restarted the server by hand.
fn confirm_restart(
	config: &Config,
	(json, out, err): (bool, &mut impl Write, &mut impl Write),
) -> ExitCode {
	let mut report = Report::new(out, json);
	match split_state::mark_restarted(&config.data_dir, super::now_epoch()) {
		Ok(settled) if settled.is_empty() => {
			report.line("nothing pending: no split is waiting for a restart");
			report.object(serde_json::json!({ "result": "unchanged", "action": "split-restarted" }))
		}
		Ok(settled) => {
			report.line(format_args!(
				"recorded that the server runs the moved keys of {}; the overlap before the shared key's records may go counts from now",
				settled.join(", ")
			));
			report.object(serde_json::json!({
				"result": "restarted", "action": "split-restarted", "domains": settled,
			}))
		}
		Err(why) => {
			crate::cli::style::error_to(err, format_args!("{why}"));
			ExitCode::FAILURE
		}
	}
}

/// Write the entries and restart: the one step that changes what signs.
fn switch(
	path: &Path,
	config: &Config,
	(plan, moves, stale): (&plan::Plan, &[Move], &[Stale]),
	report: &mut Report<'_>,
	err: &mut impl Write,
	restart: impl FnOnce(&Config, crate::cli::stack::StackAction) -> ExitCode,
) -> ExitCode {
	// What a later run needs is written first: the moved domains and the shared
	// key's selectors they leave behind. A run that dies after this and before
	// the entries are saved leaves a record of a move that did not happen,
	// which a retry settles; the other order could leave entries nobody
	// remembers.
	for m in moves {
		let selectors = stale
			.iter()
			.filter(|record| record.domain == m.domain)
			.map(|record| split_state::StaleSelector {
				selector: record.selector.clone(),
				expected: record.expected.clone(),
			})
			.collect();
		if let Err(why) =
			split_state::record_written(&config.data_dir, &m.domain, super::now_epoch(), selectors)
		{
			crate::cli::style::error_to(err, format_args!("dkim split refused: {why}"));
			return ExitCode::FAILURE;
		}
	}
	let mut document = match ConfigDocument::open(path) {
		Ok(document) => document,
		Err(error) => {
			crate::cli::style::error_to(err, error);
			return ExitCode::FAILURE;
		}
	};
	for m in moves {
		if let Err(error) = add_entry(&mut document, &m.domain, &m.keys) {
			crate::cli::style::error_to(err, error);
			return ExitCode::FAILURE;
		}
	}
	let edited = match document.config() {
		Ok(edited) => edited,
		Err(error) => {
			crate::cli::style::error_to(err, error);
			return ExitCode::FAILURE;
		}
	};
	let outcome = match document.commit() {
		Ok(outcome) => outcome,
		Err(error) => {
			crate::cli::style::error_to(err, error);
			return ExitCode::FAILURE;
		}
	};
	for m in moves {
		report.line(format_args!(
			"{} signs with {} from the next start",
			m.domain, m.keys.selector
		));
	}
	// Only a restart that is confirmed makes the new keys the ones signing;
	// until then the domains are pending and `--finish` retires nothing.
	let (confirmed, reload) = match restart_onto(&edited, outcome, err, restart) {
		Ok(done) => done,
		Err(code) => return code,
	};
	report.line(format_args!(
		"{} keeps the [dkim] key; the shared key is still published at the domains that left it",
		plan.keeps
	));
	let pending_code = (!confirmed).then(|| restart_pending(report));
	let shown: Vec<_> = moves
		.iter()
		.map(|m| (m.domain.clone(), m.keys.clone()))
		.collect();
	let mut result = describe(plan, &shown);
	report_stale(report, &mut result, stale);
	result["result"] = if confirmed {
		"split"
	} else {
		"restart-pending"
	}
	.into();
	result["action"] = "split".into();
	result["reload"] = reload.name().into();
	let code = report.object(result);
	match pending_code {
		Some(pending) if code == ExitCode::SUCCESS => pending,
		_ => code,
	}
}

#[cfg(test)]
mod tests;
