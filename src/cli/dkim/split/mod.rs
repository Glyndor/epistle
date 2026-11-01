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
use crate::dns::provider::DnsProvider;
use crate::spf::DnsLookup;

mod plan;
mod publish;

/// How the command is asked to run.
pub(super) struct Options {
	/// Print the plan and change nothing.
	pub dry_run: bool,
	/// Seconds to wait for the new records to show in DNS.
	pub wait: u64,
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
	plan.moves
		.iter()
		.map(|domain| {
			let (keys, _) = domain_keys::ensure(&config.data_dir, domain, plan.dual_signing, now)?;
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
	let plan = match plan::build(config) {
		Ok(Some(plan)) => plan,
		Ok(None) => {
			let mut report = Report::new(out, json);
			report.line("nothing to split: every hosted domain has a key of its own");
			return report.object(serde_json::json!({ "result": "unchanged", "action": "split" }));
		}
		Err(reason) => {
			crate::cli::style::error_to(err, format_args!("dkim split refused: {reason}"));
			return ExitCode::FAILURE;
		}
	};
	let planned = |plan: &plan::Plan| -> Result<Vec<(String, DomainKeys)>, String> {
		plan.moves
			.iter()
			.map(|domain| {
				domain_keys::planned(&config.data_dir, domain, plan.dual_signing, now)
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
		report.line("dry run: nothing changed");
		let mut result = describe(&plan, &shown);
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
		let mut result = describe(&plan, &shown);
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
	switch(path, (&plan, &moves), &mut report, err, restart)
}

/// Write the entries and restart: the one step that changes what signs.
fn switch(
	path: &Path,
	(plan, moves): (&plan::Plan, &[Move]),
	report: &mut Report<'_>,
	err: &mut impl Write,
	restart: impl FnOnce(&Config, crate::cli::stack::StackAction) -> ExitCode,
) -> ExitCode {
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
	let (code, reload) =
		match crate::cli::config_edit::after_change_reporting(&edited, outcome, true, err, restart)
		{
			Ok(done) => done,
			Err(ResourceError::Refusal(message) | ResourceError::Failure(message)) => {
				crate::cli::style::error_to(err, message);
				return ExitCode::FAILURE;
			}
		};
	report.line(format_args!(
		"{} keeps the [dkim] key; the records of that key at the other domains stay published until you remove them",
		plan.keeps
	));
	let shown: Vec<_> = moves
		.iter()
		.map(|m| (m.domain.clone(), m.keys.clone()))
		.collect();
	let mut result = describe(plan, &shown);
	result["result"] = "split".into();
	result["action"] = "split".into();
	result["reload"] = reload.name().into();
	if code == ExitCode::SUCCESS {
		report.object(result)
	} else {
		code
	}
}

#[cfg(test)]
mod tests;
