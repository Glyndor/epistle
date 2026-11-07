//! Withdraw what the publisher wrote, as its ledgers list it.
//!
//! A ledger record still in the zone exactly as written, and alone in its
//! slot, is removed. Anything else is reported and left: a record edited by
//! hand since, one that shares its slot with somebody else's, one under a
//! delegation, and the DKIM keys, which may still sign mail and are retired
//! by the key rotation. Nothing outside the ledgers is touched.
//!
//! The removal takes the record epistle wrote and nothing else: the exact
//! removal of the provider contract is asked for first, so a record another
//! account wrote between the listing and the removal is still there.

use std::time::Duration;

use serde::Serialize;

use super::remove::remove;
use super::slot::{is_dkim, slot_of};
use super::survey::within;
use super::{Ledger, store};
use crate::config::Config;
use crate::dns::names::{canonical_name, in_domain};
use crate::dns::provider::{DnsProvider, DnsRecord, ProviderError};
use crate::dns::rrset::{Cuts, same_record};

/// One ledger record and what undoing does with it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UndoEntry {
	/// The zone.
	pub zone: String,
	/// The record as the publisher wrote it.
	pub record: DnsRecord,
	/// `remove`, `absent` or `left`.
	pub outcome: &'static str,
	/// Why, for the operator.
	pub reason: String,
}

/// What undoing did, or would do with a dry run.
#[derive(Debug, Default, Serialize)]
pub struct UndoReport {
	/// Every ledger record in scope, newest first per zone.
	pub entries: Vec<UndoEntry>,
	/// Why the run stopped, when it did.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub failure: Option<String>,
}

/// Undo the ledgers in scope. Every zone is read before anything is
/// removed; a zone that cannot be read stops the run with nothing written.
pub async fn undo(
	config: &Config,
	provider: &dyn DnsProvider,
	domain: Option<&str>,
	dry_run: bool,
	timeout: Duration,
) -> Result<UndoReport, String> {
	let data_dir = &config.data_dir;
	let mut read = Vec::new();
	for zone in store::zones(data_dir)? {
		let ledger = store::load(data_dir, &zone)?;
		if ledger.entries.is_empty() {
			continue;
		}
		let listing = match within(timeout, provider.list(&zone)).await {
			Ok(listing) => listing,
			Err(ProviderError::Unsupported) => {
				return Err(format!(
					"this DNS provider cannot list the {zone} zone, so epistle cannot tell whether its records are still as it wrote them; nothing was removed"
				));
			}
			Err(error) => return Err(format!("reading the {zone} zone failed: {error}")),
		};
		read.push((zone, ledger, listing));
	}
	let mut report = UndoReport::default();
	for (zone, mut ledger, listing) in read {
		let cuts = Cuts::new(&canonical_name(&zone), &listing);
		let held: Vec<DnsRecord> = ledger.records().into_iter().rev().collect();
		for record in held {
			let name = canonical_name(&record.name);
			if domain.is_some_and(|d| !in_domain(&name, d)) {
				continue;
			}
			let (outcome, reason) = decide(&record, &name, &listing, &cuts);
			if outcome == "remove"
				&& !dry_run && let Err(error) = remove(provider, &zone, &record, timeout).await
			{
				report.failure = Some(format!(
					"removing {name} {} failed: {error}",
					record.kind.as_str()
				));
				return Ok(report);
			}
			if outcome != "left" && !dry_run {
				forget(config, &mut ledger, &record)?;
			}
			report.entries.push(UndoEntry {
				zone: zone.clone(),
				record,
				outcome,
				reason,
			});
		}
	}
	Ok(report)
}

/// Decide what undoing does with one ledger record.
fn decide(
	record: &DnsRecord,
	name: &str,
	listing: &[DnsRecord],
	cuts: &Cuts,
) -> (&'static str, String) {
	let kind = record.kind.as_str();
	if let Some(cut) = cuts.above(name) {
		return (
			"left",
			format!(
				"{} is delegated to other nameservers",
				super::from_zone(cut)
			),
		);
	}
	if is_dkim(record) {
		return (
			"left",
			format!(
				"{name} is a DKIM key that may still sign mail; `epistle dkim cleanup` retires keys"
			),
		);
	}
	let slot = slot_of(record, listing);
	match slot.as_slice() {
		[] => ("absent", format!("{name} {kind} is no longer in the zone")),
		[only] if same_record(only, record) => {
			("remove", format!("{name} {kind} was published by epistle"))
		}
		_ if !slot.iter().any(|r| same_record(r, record)) => (
			"absent",
			format!("{name} {kind} was changed since it was published; left as is"),
		),
		_ => (
			"left",
			format!("{name} {kind} shares its place with records epistle did not publish"),
		),
	}
}

fn forget(config: &Config, ledger: &mut Ledger, record: &DnsRecord) -> Result<(), String> {
	ledger.forget(record);
	store::store(&config.data_dir, ledger)
}
