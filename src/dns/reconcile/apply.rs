//! Apply a planned zone, keeping the ledger true to what went out.
//!
//! A record about to be written enters the ledger first, so a write whose
//! answer is lost is still known as epistle's own at the next run; a record
//! removed leaves it once the provider accepted the removal. The first write
//! that fails stops the run: the rest of the plan was made against a zone
//! that may have changed.
//!
//! A write that failed and left nothing in the zone takes the claim back:
//! the ledger says what epistle published, and it never says it published a
//! record that is not there.
//!
//! A provider that checks a precondition gets the exact set at the name and
//! type, applied only if the zone still holds what was read. Every other
//! provider gets the ordinary upsert or delete, which the plan only asks for
//! when nothing in the slot belongs to somebody else.

use std::path::Path;
use std::time::Duration;

use super::slot::same_slot;
use super::survey::{ZoneRun, within};
use super::{Action, Entry, store};
use crate::dns::names::canonical_name;
use crate::dns::provider::{DnsProvider, DnsRecord, RecordKind};
use crate::dns::publish::provider::{
	Change, Guard, ObservedRecord, OperationOutcome, Precondition, Receipt,
};
use crate::dns::rrset::same_record;

/// What applying did.
#[derive(Debug, Default)]
pub struct Report {
	/// The entries applied, with their zone, in order.
	pub applied: Vec<(String, Entry)>,
	/// Why the run stopped, when it did.
	pub failure: Option<String>,
}

/// Where the writes go and what they remember.
pub struct Target<'a> {
	/// The provider.
	pub provider: &'a dyn DnsProvider,
	/// The data directory, where the ledgers live.
	pub data_dir: &'a Path,
	/// The mail host, whose TLSA state learns the values written.
	pub hostname: &'a str,
	/// How long one provider call may take.
	pub timeout: Duration,
	/// The current time, seconds since the epoch.
	pub now: u64,
}

/// Apply every zone in order. The caller holds the ledger lock.
pub async fn apply(target: &Target<'_>, zones: Vec<ZoneRun>) -> Report {
	let mut report = Report::default();
	for zone in zones {
		if let Err(failure) = apply_zone(target, zone, &mut report).await {
			report.failure = Some(failure);
			break;
		}
	}
	report
}

/// The writer of one zone: what it holds now, as far as this run knows.
struct Writer<'a> {
	target: &'a Target<'a>,
	zone: String,
	guard: Guard,
	revision: Option<String>,
	observed: Vec<ObservedRecord>,
}

async fn apply_zone(target: &Target<'_>, run: ZoneRun, report: &mut Report) -> Result<(), String> {
	let mut ledger = run.ledger;
	let mut writer = Writer {
		target,
		zone: run.plan.zone.clone(),
		guard: run.snapshot.guard,
		revision: run.snapshot.revision,
		observed: run.snapshot.records,
	};
	for entry in run.plan.entries {
		let record = &entry.record;
		let what = format!(
			"{} {} {}",
			entry.action_word(),
			canonical_name(&record.name),
			record.kind.as_str()
		);
		match entry.action {
			Action::Create | Action::Update => {
				// The intent is written first, so a write whose answer is
				// lost is still known as epistle's own at the next run. A
				// write that failed leaves nothing behind, and the claim
				// is taken back: the ledger must not say epistle published
				// a record that is not there.
				let claimed = ledger.clone();
				ledger.remember(record, None, target.now);
				store::store(target.data_dir, &ledger).map_err(|e| {
					format!("{what}: the ledger could not be saved ({e}); nothing was written")
				})?;
				let identity = match writer.put(record).await {
					Ok(identity) => identity,
					Err(error) => {
						if !written(&writer, record).await {
							ledger = claimed;
							store::store(target.data_dir, &ledger).map_err(|e| {
								format!("{what} failed and the claim could not be taken back ({e})")
							})?;
						}
						return Err(format!("{what} failed: {error}"));
					}
				};
				if identity.is_some() {
					ledger.remember(record, identity, target.now);
					store::store(target.data_dir, &ledger).map_err(|e| {
						format!("{what} was published but the ledger could not be saved ({e})")
					})?;
				}
				if record.kind == RecordKind::Tlsa {
					remember_tlsa(target, record);
				}
			}
			Action::Remove => {
				writer
					.remove(record)
					.await
					.map_err(|e| format!("{what} failed: {e}"))?;
				ledger.forget(record);
				store::store(target.data_dir, &ledger).map_err(|e| {
					format!(
						"{what} was done but the ledger could not be saved ({e}); remove the entry by hand"
					)
				})?;
			}
			Action::Gone => {
				ledger.forget(record);
				store::store(target.data_dir, &ledger)
					.map_err(|e| format!("the ledger could not be saved ({e})"))?;
			}
			_ => continue,
		}
		report.applied.push((writer.zone.clone(), entry));
	}
	Ok(())
}

/// The certificate refresh replaces only TLSA values it knows as its own,
/// so a value the publisher wrote is added to its state.
fn remember_tlsa(target: &Target<'_>, record: &DnsRecord) {
	let mut state = crate::dns::tlsa::State::load(target.data_dir, target.hostname);
	let others = state.managed.clone();
	state.intend(&record.value, &others);
	if let Err(error) = state.save(target.data_dir) {
		tracing::warn!(%error, "cannot store the TLSA state after publishing the TLSA record");
	}
}

/// Whether the zone holds `record` after a write that failed.
///
/// A write whose answer was lost left the record in the zone: the write
/// happened and only the answer did not arrive. A write that failed left it
/// out. The zone tells the two apart, and the ledger may only claim what is
/// really there.
///
/// A zone that cannot be read leaves the claim in doubt, and a claim in
/// doubt is taken back: a record that is there and not claimed is left
/// alone, while a record that is not there and claimed would be taken away
/// from whoever published it later.
async fn written(writer: &Writer<'_>, record: &DnsRecord) -> bool {
	let provider = writer.target.provider;
	match within(writer.target.timeout, provider.list(&writer.zone)).await {
		Ok(listing) => listing.iter().any(|held| same_record(held, record)),
		Err(_) => false,
	}
}

impl Writer<'_> {
	/// The set the zone holds at the name and type of `record`.
	fn set_of(&self, record: &DnsRecord) -> Vec<ObservedRecord> {
		let name = canonical_name(&record.name);
		self.observed
			.iter()
			.filter(|o| o.record.kind == record.kind && canonical_name(&o.record.name) == name)
			.cloned()
			.collect()
	}

	/// Write `record` in its slot. Returns the identity the provider gave it.
	async fn put(&mut self, record: &DnsRecord) -> Result<Option<String>, String> {
		if self.guard == Guard::Unchecked {
			let provider = self.target.provider;
			within(
				self.target.timeout,
				provider.upsert(&self.zone, record.clone()),
			)
			.await
			.map_err(|e| e.to_string())?;
			return Ok(None);
		}
		let before = self.set_of(record);
		let mut after: Vec<DnsRecord> = before
			.iter()
			.map(|o| o.record.clone())
			.filter(|r| !same_slot(r, record))
			.collect();
		after.push(record.clone());
		self.guarded(record, before, after).await
	}

	/// Remove `record` alone.
	async fn remove(&mut self, record: &DnsRecord) -> Result<(), String> {
		if self.guard == Guard::Unchecked {
			let provider = self.target.provider;
			let zone = self.zone.clone();
			let timeout = self.target.timeout;
			// The exact removal: the record epistle wrote and nothing
			// else, so a record another account wrote in between stays.
			super::remove::remove(provider, &zone, record, timeout)
				.await
				.map_err(|e| e.to_string())?;
			return Ok(());
		}
		let before = self.set_of(record);
		let after = before
			.iter()
			.map(|o| o.record.clone())
			.filter(|r| !same_record(r, record))
			.collect();
		self.guarded(record, before, after).await.map(|_| ())
	}

	/// Apply `before` to `after` at the name and type of `record`, under the
	/// precondition that the zone still holds what was read.
	async fn guarded(
		&mut self,
		record: &DnsRecord,
		before: Vec<ObservedRecord>,
		after: Vec<DnsRecord>,
	) -> Result<Option<String>, String> {
		let operation_id = format!("epistle-publish-{}", uuid::Uuid::now_v7());
		let change = Change {
			name: record.name.clone(),
			kind: record.kind.clone(),
			before,
			after: after.clone(),
			precondition: match &self.revision {
				Some(revision) => Precondition::Revision(revision.clone()),
				None => Precondition::Identity,
			},
			operation_id: operation_id.clone(),
		};
		let provider = self.target.provider;
		let (identity, revision) = match provider.apply_guarded(&self.zone, change).await {
			Receipt::Applied { identity, revision } => (identity, revision),
			Receipt::Unknown => match provider.lookup_operation(&operation_id).await {
				Ok(OperationOutcome::Applied) => (None, None),
				_ => {
					return Err(
						"the provider did not confirm the change; nothing else is written until it is resolved"
							.into(),
					);
				}
			},
			Receipt::PreconditionFailed => {
				return Err("the zone changed since it was read; nothing was written".into());
			}
			Receipt::Unsupported => {
				return Err("the provider applies no guarded change; nothing was written".into());
			}
			Receipt::Rejected(reason) => {
				return Err(format!(
					"the provider refused the change: {}",
					crate::cli::term::sanitize(&reason)
				));
			}
		};
		// What this run knows of the zone now: the set it wrote.
		let name = canonical_name(&record.name);
		self.observed
			.retain(|o| !(o.record.kind == record.kind && canonical_name(&o.record.name) == name));
		self.observed
			.extend(after.into_iter().map(|record| ObservedRecord {
				record,
				identity: None,
			}));
		self.revision = revision;
		Ok(identity)
	}
}

impl Entry {
	/// The verb the entry is shown with.
	pub fn action_word(&self) -> &'static str {
		match self.action {
			Action::Create => "create",
			Action::Update => "update",
			Action::Remove => "remove",
			Action::Present => "present",
			Action::Adopted => "adopted",
			Action::Conflict => "conflict",
			Action::Kept => "kept",
			Action::Gone => "gone",
			Action::Skipped => "skipped",
		}
	}
}
