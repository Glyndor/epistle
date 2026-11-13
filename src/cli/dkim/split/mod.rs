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
//!
//! When the wait ends with records still missing, the report asks the zone's
//! own nameservers what they serve and names the cause: a record the zone
//! publishes and the host's resolver hides behind a cached negative answer,
//! or a record the zone does not serve yet. The cause is reported, not acted
//! on: signing still switches only when the host's resolver shows the record.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use crate::cli::json_out::Report;
use crate::config::Config;
use crate::dkim::domain_keys::{self, DomainKeys};
use crate::dkim::split_state;
use crate::dns::authoritative::{AuthorityLookup, SystemAuthority};
use crate::dns::provider::DnsProvider;
use crate::spf::DnsLookup;

use moves::{describe, keys_of, make_keys, report_stale, stale_of};
use restart::{confirm_restart, nothing_to_split, restart_onto, restart_pending};
use switch::switch;

mod diagnosis;
mod finish;
mod moves;
mod plan;
mod publish;
mod restart;
mod switch;

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
	/// The zone's own nameservers, asked when a record the resolver does not
	/// show has to be told apart from one the zone does not serve.
	pub authority: Option<&'a dyn AuthorityLookup>,
	/// The pauses between the queries that look for the records.
	pub waits: Vec<Duration>,
}

/// How long a run waits for another one on the same data directory.
const LOCK_WAIT: Duration = if cfg!(test) {
	Duration::from_secs(3)
} else {
	Duration::from_secs(30)
};

/// How many times a run follows a `data_dir` that changed while it waited.
const DATA_DIR_RETRIES: u32 = 3;

/// The seconds between queries while waiting for the records.
const POLL_SECONDS: u64 = 5;

/// Run `dkim split` against the configuration at `path`.
pub(super) fn run(path: &Path, options: &Options, json: bool, out: &mut impl Write) -> ExitCode {
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
	let waits = vec![Duration::from_secs(POLL_SECONDS); (options.wait / POLL_SECONDS) as usize];
	// The zone's own nameservers are asked when a record does not show up,
	// to tell a record the zone does not serve from one the host's resolver
	// is hiding. A resolver that cannot be built leaves the cause unknown,
	// which the report says.
	let authority = SystemAuthority::from_system().ok();
	let mut err = crate::cli::style::stderr();
	runtime.block_on(run_locked(
		path,
		options,
		|config| Services {
			provider: config.dns.build_for_host(&config.hostname),
			resolver: &resolver,
			authority: authority
				.as_ref()
				.map(|authority| authority as &dyn AuthorityLookup),
			waits,
		},
		(json, out, &mut err),
		crate::cli::stack::run,
	))
}

/// Take the lock of the data directory, then read the configuration and build
/// the services, then run. One run at a time per data directory, dry runs
/// included: a plan made from a configuration read before the lock would be
/// the plan of a state another run has since changed, and a run that waited
/// would act on it.
pub(super) async fn run_locked<'a>(
	path: &Path,
	options: &Options,
	make_services: impl FnOnce(&Config) -> Services<'a>,
	(json, out, err): (bool, &mut impl Write, &mut impl Write),
	restart: impl FnOnce(&Config, crate::cli::stack::StackAction) -> ExitCode,
) -> ExitCode {
	// The lock is named by the data directory, so the configuration is read
	// once to learn it and again, under the lock, to act on. If a run that
	// waited finds the directory changed, the lock it holds is the old one's:
	// it is let go and the new directory's is taken, so the run is always
	// under the lock of the directory it acts on.
	let mut data_dir = match Config::load(path) {
		Ok(config) => config.data_dir,
		Err(error) => {
			crate::cli::style::error_to(err, error);
			return ExitCode::FAILURE;
		}
	};
	let mut attempts = 0;
	let (_held, config) = loop {
		// A dry run only looks: it waits for a run that is changing things
		// and never creates the lock file.
		let held = if options.dry_run {
			split_state::observe(&data_dir, LOCK_WAIT)
		} else {
			split_state::lock(&data_dir, LOCK_WAIT).map(Some)
		};
		let held = match held {
			Ok(held) => held,
			Err(why) => {
				crate::cli::style::error_to(err, format_args!("dkim split refused: {why}"));
				return ExitCode::FAILURE;
			}
		};
		let config = match Config::load(path) {
			Ok(config) => config,
			Err(error) => {
				crate::cli::style::error_to(err, error);
				return ExitCode::FAILURE;
			}
		};
		if config.data_dir == data_dir {
			break (held, config);
		}
		attempts += 1;
		if attempts >= DATA_DIR_RETRIES {
			crate::cli::style::error_to(
				err,
				format_args!(
					"dkim split refused: data_dir keeps changing in {}; run it again once it is settled",
					path.display()
				),
			);
			return ExitCode::FAILURE;
		}
		data_dir = config.data_dir;
	};
	let services = make_services(&config);
	split(path, &config, options, &services, (json, out, err), restart).await
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
	if options.restarted {
		return confirm_restart(config, (json, out, err));
	}
	if options.finish {
		return finish::finish(config, options, services, (json, out, err), now).await;
	}
	let plan = match plan::build(config) {
		Ok(Some(plan)) => plan,
		Ok(None) => return nothing_to_split(config, options, (json, out, err), restart),
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
			for (selector, file) in keys_of(keys) {
				report.line(format_args!(
					"give {domain} a key of its own ({selector}) at {}",
					file.display()
				));
				report.line(format_args!(
					"publish TXT {selector}._domainkey.{domain}, wait until it resolves, then switch signing"
				));
			}
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
	let mut automatic: Vec<(String, publish::Record)> = Vec::new();
	let mut manual: Vec<publish::Record> = Vec::new();
	for record in &records {
		match services
			.provider
			.as_ref()
			.and(publish::zone_of(config, &record.name))
		{
			Some(zone) => automatic.push((zone, record.clone())),
			None => manual.push(record.clone()),
		}
	}
	if let Some(provider) = &services.provider {
		let failed = publish::publish(provider.as_ref(), &automatic).await;
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
	for (_, record) in &automatic {
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
		let causes = diagnosis::diagnose(&absent, services.resolver, services.authority).await;
		for (missing, diagnosis) in absent.iter().zip(causes.iter()) {
			report.line(format_args!("not visible yet: {}", missing.record.name));
			report.line(format_args!("  {}", diagnosis.cause.explanation()));
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
			.map(|missing| missing.record.name.clone())
			.collect::<Vec<_>>()
			.into();
		result["causes"] = causes
			.iter()
			.map(|diagnosis| {
				serde_json::json!({
					"name": diagnosis.name,
					"cause": diagnosis.cause.name(),
					"negative_ttl": diagnosis.cause.ttl(),
				})
			})
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

#[cfg(test)]
mod tests;
