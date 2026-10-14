//! Publishing a lockdown plan and undoing it. Both keep the journal true
//! to the zone: publishing records each write as soon as the provider
//! accepts it, so a failure halfway leaves the journal with exactly what
//! went out; undoing touches only a journal record that is still in the
//! zone as the lockdown wrote it and alone of its kind at its name, so a
//! record the operator changed since is left in place and reported.

use super::{Journal, JournalEntry, Plan, PlanEntry, canonical_name, same_record};
use crate::dns::provider::{DnsProvider, DnsRecord, RecordKind, txt_purpose};

/// Publishing stopped partway.
#[derive(Debug)]
pub struct PublishFailure {
	/// What failed, for the operator.
	pub message: String,
	/// The journal with every record that did go out.
	pub journal: Journal,
}

/// Publish every entry of `plan` through `provider`, in order. After each
/// write the provider accepts, the journal (the earlier one plus this
/// run's writes) is handed to `persist`; a write the provider refuses, or
/// a journal `persist` cannot store, stops the run before the next write.
pub async fn publish_plan(
	provider: &dyn DnsProvider,
	zone: &str,
	plan: &Plan,
	journal: Option<&Journal>,
	persist: &mut dyn FnMut(&Journal) -> Result<(), String>,
) -> Result<Journal, PublishFailure> {
	let mut journal = journal
		.cloned()
		.unwrap_or_else(|| Journal::new(plan.domain.clone()));
	for entry in &plan.entries {
		let record = &entry.record;
		if let Err(error) = provider.upsert(zone, record.clone()).await {
			return Err(PublishFailure {
				message: format!(
					"publishing {} {} failed: {error}",
					record.kind.as_str(),
					record.name
				),
				journal,
			});
		}
		remember(&mut journal, entry);
		if let Err(error) = persist(&journal) {
			return Err(PublishFailure {
				message: format!(
					"{} {} was published but the journal could not be saved ({error}); remove it by hand if you undo",
					record.kind.as_str(),
					record.name
				),
				journal,
			});
		}
	}
	Ok(journal)
}

/// Add a published entry to the journal. A record that replaces one the
/// journal already holds (the next DMARC step) takes its place and keeps
/// the operator's original, so `--undo` restores what was there before
/// the first run.
fn remember(journal: &mut Journal, entry: &PlanEntry) {
	let record = &entry.record;
	let slot = journal
		.entries
		.iter_mut()
		.find(|held| same_slot(&held.record, record));
	match slot {
		Some(held) => held.record = record.clone(),
		None => journal.entries.push(JournalEntry {
			record: record.clone(),
			replaced: entry.replaces.clone(),
		}),
	}
}

/// Whether two records sit in the same place under the provider contract:
/// same name and kind and, for TXT, the same purpose (version tag), or
/// the same value when untagged.
fn same_slot(a: &DnsRecord, b: &DnsRecord) -> bool {
	a.kind == b.kind
		&& canonical_name(&a.name) == canonical_name(&b.name)
		&& (a.kind != RecordKind::Txt
			|| match (txt_purpose(&a.value), txt_purpose(&b.value)) {
				(Some(x), Some(y)) => x == y,
				(None, None) => crate::dns::txt::same_txt_value(&a.value, &b.value),
				_ => false,
			})
}

/// A journal record the operator changed since the lockdown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UndoChanged {
	/// The record as the lockdown published it.
	pub record: DnsRecord,
	/// The values at that name and kind now.
	pub now: Vec<String>,
}

/// What `--undo` did, or would do with `--dry-run`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UndoReport {
	/// Records removed: the lockdown added them where there was none.
	pub deleted: Vec<DnsRecord>,
	/// Records put back: the operator's DMARC the lockdown replaced.
	pub restored: Vec<DnsRecord>,
	/// Records the operator changed since; left in place.
	pub changed: Vec<UndoChanged>,
	/// Records already gone; nothing to do.
	pub absent: Vec<DnsRecord>,
}

/// Undoing stopped partway.
#[derive(Debug)]
pub struct UndoFailure {
	/// What failed, for the operator.
	pub message: String,
	/// What was done before the failure.
	pub report: UndoReport,
	/// The journal entries not undone yet, to keep for the next try.
	pub remaining: Journal,
}

/// Undo `journal` through `provider`, newest record first. A record still
/// in the zone exactly as published, and alone of its kind (TXT: of its
/// purpose) at its name, is removed, or replaced by the record it replaced;
/// anything else is reported and left alone. Nothing outside the journal
/// is touched. With `dry_run` the provider is only read.
pub async fn undo_journal(
	provider: &dyn DnsProvider,
	zone: &str,
	journal: &Journal,
	dry_run: bool,
) -> Result<UndoReport, Box<UndoFailure>> {
	let mut report = UndoReport::default();
	let existing = match provider.list(zone).await {
		Ok(existing) => existing,
		Err(error) => {
			return Err(Box::new(UndoFailure {
				message: format!("reading the zone {zone} failed: {error}"),
				report,
				remaining: journal.clone(),
			}));
		}
	};
	for (index, entry) in journal.entries.iter().enumerate().rev() {
		let ours = &entry.record;
		let siblings: Vec<&DnsRecord> = existing.iter().filter(|r| same_slot(r, ours)).collect();
		let listed = match siblings.as_slice() {
			[] => {
				report.absent.push(ours.clone());
				continue;
			}
			[only] if same_record(only, ours) => (*only).clone(),
			_ => {
				report.changed.push(UndoChanged {
					record: ours.clone(),
					now: siblings.iter().map(|r| r.value.clone()).collect(),
				});
				continue;
			}
		};
		let outcome = match (&entry.replaced, dry_run) {
			(_, true) => Ok(()),
			(Some(original), false) => provider.upsert(zone, original.clone()).await,
			(None, false) => provider.delete(zone, listed).await,
		};
		if let Err(error) = outcome {
			return Err(Box::new(UndoFailure {
				message: format!(
					"undoing {} {} failed: {error}",
					ours.kind.as_str(),
					ours.name
				),
				report,
				remaining: Journal {
					domain: journal.domain.clone(),
					entries: journal.entries[..=index].to_vec(),
				},
			}));
		}
		match &entry.replaced {
			Some(original) => report.restored.push(original.clone()),
			None => report.deleted.push(ours.clone()),
		}
	}
	Ok(report)
}
