//! Read everything a run needs before anything is written: the zone that
//! holds each needed record, the listing of every zone, the ledgers, and
//! the records other parts of epistle keep.
//!
//! A zone whose provider cannot be read is reported and left alone: the
//! other zones are compared and published, so one entry with a broken
//! credential does not stop every other domain from being published. A
//! ledger that cannot be read stops the run instead: without it epistle
//! does not know what it owns, and every record in it would turn foreign.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use serde::Serialize;

use super::{Ledger, ZoneInput, ZonePlan, plan_zone, store};
use crate::config::Config;
use crate::dns::names::{canonical_name, in_domain};
use crate::dns::provider::{DnsProvider, DnsRecord, ProviderError, RecordKind};
use crate::dns::publish::provider::Snapshot;
use crate::dns::records::PublishRecord;

/// A zone read and planned.
#[derive(Debug)]
pub struct ZoneRun {
	/// The plan.
	pub plan: ZonePlan,
	/// The ledger the plan was made against.
	pub ledger: Ledger,
	/// The zone as the provider listed it.
	pub snapshot: Snapshot,
	/// The lock of the zone, taken before the zone was read and held
	/// until the plan is applied. Nobody else writes the zone while this
	/// run reads it and writes the difference.
	pub lock: crate::dns::zone_lock::ZoneLock,
}

/// A zone that could not be read, and why it was left alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ZoneFailure {
	/// The zone.
	pub zone: String,
	/// Why the zone was not compared.
	pub reason: String,
}

/// A needed record no provider writes: its zone is `manual` or no `[dns]`
/// entry covers it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ByHand {
	/// The record to add by hand.
	pub record: DnsRecord,
	/// Why epistle does not write it.
	pub reason: String,
}

/// What a run read.
#[derive(Debug, Default)]
pub struct Survey {
	/// The zones a provider writes, planned.
	pub zones: Vec<ZoneRun>,
	/// The records left to the operator.
	pub by_hand: Vec<ByHand>,
	/// The zones that could not be read. The other zones were compared and
	/// are published.
	pub failures: Vec<ZoneFailure>,
}

impl Survey {
	/// Whether applying the survey changes a zone or a ledger.
	pub fn changes(&self) -> bool {
		self.zones.iter().any(|z| z.plan.changes())
	}

	/// How many entries write to a zone.
	pub fn writes(&self) -> usize {
		self.zones.iter().map(|z| z.plan.writes()).sum()
	}
}

/// What [`survey`] reads.
pub struct Context<'a> {
	/// The configuration.
	pub config: &'a Config,
	/// The provider `[dns]` builds.
	pub provider: &'a dyn DnsProvider,
	/// The records the configuration needs ([`crate::dns::desired`]).
	pub needed: &'a [PublishRecord],
	/// Only this hosted domain, or every one.
	pub domain: Option<&'a str>,
	/// How long one provider call may take.
	pub timeout: Duration,
	/// Why the needed set is incomplete ([`crate::dns::desired::Desired::incomplete`]):
	/// with a reason nothing is retired this run.
	pub incomplete: Option<&'a str>,
}

/// Read and plan every zone the run touches.
pub async fn survey(ctx: &Context<'_>) -> Result<Survey, String> {
	let config = ctx.config;
	let mut survey = Survey::default();
	let mut zones: BTreeMap<String, Vec<DnsRecord>> = BTreeMap::new();
	let mut resolved: BTreeMap<String, String> = BTreeMap::new();
	// Set when a needed name was left out because its zone could not be
	// found: the needed set is then incomplete, and a record of epistle's
	// own for that name must not be retired as if nothing needed it.
	let mut unresolved: Option<String> = None;
	for needed in ctx.needed {
		let name = canonical_name(&needed.record.name);
		if ctx.domain.is_some_and(|d| !in_domain(&name, d)) {
			continue;
		}
		let key = canonical_name(&needed.zone);
		if !config.dns.publishes(&key) {
			survey.by_hand.push(ByHand {
				record: needed.record.clone(),
				reason: format!("no [dns] entry writes the zone of {key}; add it by hand"),
			});
			continue;
		}
		let zone = match resolved.get(&key) {
			Some(zone) => zone.clone(),
			None => {
				let zone = match within(ctx.timeout, crate::dns::zone::resolve(ctx.provider, &key))
					.await
				{
					Ok(zone) => canonical_name(&zone),
					Err(error) => {
						// Same as a zone that cannot be listed: this
						// name is left alone and the others go on.
						unresolved
							.get_or_insert_with(|| format!("the zone of {key} could not be found"));
						if !survey.failures.iter().any(|f| f.zone == key) {
							survey.failures.push(ZoneFailure {
								zone: key.clone(),
								reason: format!("finding the zone of {key} failed: {error}"),
							});
						}
						continue;
					}
				};
				resolved.insert(key, zone.clone());
				zone
			}
		};
		zones.entry(zone).or_default().push(needed.record.clone());
	}
	for zone in store::zones(&config.data_dir)? {
		let touches = ctx
			.domain
			.is_none_or(|d| in_domain(d, &zone) || in_domain(&zone, d));
		if touches && config.dns.publishes(&zone) {
			zones.entry(zone).or_default();
		}
	}
	let also_ours = tlsa_values(&config.data_dir, &config.hostname);
	// The locks of the zones this run reads, held until their plans are
	// applied.
	let mut locks = crate::dns::zone_lock::Locks::default();
	for (zone, needed) in zones {
		// The lock of the zone is taken before the zone is read and held
		// until the plan is applied: the rotation that publishes in the
		// same zone waits, and the plan is made against a zone nobody
		// else is writing.
		let lock = locks.lock(&zone).await;
		let snapshot = match within(ctx.timeout, ctx.provider.publish_snapshot(&zone)).await {
			Ok(snapshot) => snapshot,
			Err(error) => {
				// The zone is left alone and the run goes on with the
				// other zones: one entry with a broken credential must
				// not stop every other domain from being published.
				survey.failures.push(ZoneFailure {
					zone: zone.clone(),
					reason: unreadable(config, &zone, &error),
				});
				continue;
			}
		};
		let ledger = store::load(&config.data_dir, &zone)?;
		let lockdown = lockdown_records(config, &zone)?;
		let existing: Vec<DnsRecord> = snapshot.records.iter().map(|o| o.record.clone()).collect();
		let plan = plan_zone(&ZoneInput {
			zone: &zone,
			needed: &needed,
			existing: &existing,
			ledger: &ledger,
			also_ours: &also_ours,
			lockdown: &lockdown,
			retire_within: ctx.domain,
			incomplete: ctx.incomplete.or(unresolved.as_deref()),
			skip: &config.skip_set(),
			flattens_apex_cname: ctx.provider.flattens_apex_cname(&zone),
		});
		survey.zones.push(ZoneRun {
			plan,
			ledger,
			snapshot,
			lock,
		});
	}
	Ok(survey)
}

/// Why the zone could not be read.
///
/// The credential comes first: an entry whose token is missing is not a
/// provider that cannot list, and the operator needs to be told which
/// one it is. Only an entry that builds a provider leaves the
/// capability as the reason.
fn unreadable(config: &Config, zone: &str, error: &ProviderError) -> String {
	match error {
		ProviderError::Unsupported => match config
			.dns
			.entry_for(zone)
			.and_then(|dns| dns.build_problem())
		{
			Some(problem) => format!("the [dns] entry for {zone} cannot publish: {problem}"),
			None => format!(
				"this DNS provider cannot list the {zone} zone, so epistle cannot tell its own records from anybody else's"
			),
		},
		other => format!("reading the {zone} zone failed: {other}"),
	}
}

/// Run `op` with a deadline; running out is a provider failure.
pub(super) async fn within<T>(
	timeout: Duration,
	op: impl Future<Output = Result<T, ProviderError>>,
) -> Result<T, ProviderError> {
	tokio::time::timeout(timeout, op).await.unwrap_or_else(|_| {
		Err(ProviderError::Remote(format!(
			"no answer within {} seconds",
			timeout.as_secs()
		)))
	})
}

/// The TLSA values the certificate refresh published for `hostname`.
fn tlsa_values(data_dir: &Path, hostname: &str) -> Vec<DnsRecord> {
	crate::dns::tlsa::State::load(data_dir, hostname)
		.managed
		.into_iter()
		.map(|value| {
			DnsRecord::new(
				format!("_25._tcp.{hostname}"),
				RecordKind::Tlsa,
				value,
				crate::dns::records::TTL,
			)
		})
		.collect()
}

/// The records `dns lockdown` published for the hosted domains in `zone`.
/// A journal that cannot be read stops the run: without it the publisher
/// could replace a policy the lockdown is moving.
fn lockdown_records(config: &Config, zone: &str) -> Result<Vec<DnsRecord>, String> {
	let mut records = Vec::new();
	for domain in &config.domains {
		let domain = canonical_name(domain);
		if !in_domain(&domain, zone) {
			continue;
		}
		let path = config
			.data_dir
			.join("dns-lockdown")
			.join(format!("{domain}.json"));
		let text = match std::fs::read_to_string(&path) {
			Ok(text) => text,
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
			Err(error) => return Err(format!("cannot read {}: {error}", path.display())),
		};
		let journal: crate::dns::lockdown::Journal = serde_json::from_str(&text)
			.map_err(|error| format!("the journal {} is not readable: {error}", path.display()))?;
		records.extend(journal.entries.into_iter().map(|e| e.record));
	}
	Ok(records)
}
