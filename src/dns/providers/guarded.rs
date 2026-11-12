//! The guarded write of a provider that addresses its records by id.
//!
//! Such a provider offers no revision of a zone and no condition on a write,
//! so the precondition is the one it can check: the set at the name and type
//! is read again right before the write and must still be the one the plan
//! was made against, with the same ids and the same values. The check and
//! the write are two requests, so a record another account changes in
//! between is not detected; what the write does is bounded all the same,
//! because it addresses records by id: a record the plan did not list is
//! never updated or deleted, and a record added in between stays.
//!
//! The change is applied as the difference between the set that was read and
//! the set to write: a record that stays is not touched, a record that is
//! replaced is updated in place by its id, a new one is created and one that
//! leaves is deleted by its id. The updates and the creations go first, so
//! the name is never left without a record while the change is applied.
//!
//! A provider supplies the five requests in [`ById`]; the check, the plan
//! and the verdict are the same for all of them.

use crate::dns::names::canonical_name;
use crate::dns::provider::{DnsRecord, ProviderError};
use crate::dns::publish::provider::{Change, Precondition, Receipt};
use crate::dns::rrset::same_record;

/// Why a change did not go out as a whole.
#[derive(Debug)]
pub(crate) enum Stop {
	/// The set is not the one the plan was made against.
	Changed,
	/// Nothing was written and the provider will not take the change.
	Refused(String),
	/// A write was sent and its outcome is not known.
	Unknown,
}

impl From<ProviderError> for Stop {
	fn from(error: ProviderError) -> Self {
		Stop::Refused(error.to_string())
	}
}

/// A record as the provider lists it now, with the id it addresses it by.
#[derive(Debug, Clone)]
pub(crate) struct Fresh {
	/// The provider's id of the record.
	pub id: String,
	/// The record, read back into the shape the rest of epistle uses.
	pub record: DnsRecord,
}

/// The entries of `listed` at the name and type of `change`.
pub(crate) fn at_name(change: &Change, listed: impl IntoIterator<Item = Fresh>) -> Vec<Fresh> {
	let name = canonical_name(&change.name);
	listed
		.into_iter()
		.filter(|f| f.record.kind == change.kind && canonical_name(&f.record.name) == name)
		.collect()
}

/// The entries of `fresh` that stand for the records of `change.before`, in
/// the order of `before`, when the set is still the one the plan saw: the
/// same number of records, each with the id the snapshot gave it (when it
/// gave one) and its value.
pub(crate) fn held(change: &Change, fresh: &[Fresh]) -> Option<Vec<usize>> {
	match change.precondition {
		Precondition::Absent => {
			return (fresh.is_empty() && change.before.is_empty()).then(Vec::new);
		}
		Precondition::Revision(_) => return None,
		Precondition::Identity => {}
	}
	if fresh.len() != change.before.len() {
		return None;
	}
	let mut used = vec![false; fresh.len()];
	let mut matched = Vec::with_capacity(fresh.len());
	for seen in &change.before {
		let index = fresh.iter().enumerate().position(|(i, now)| {
			!used[i]
				&& seen.identity.as_deref().is_none_or(|id| id == now.id)
				&& same_record(&seen.record, &now.record)
		})?;
		used[index] = true;
		matched.push(index);
	}
	Some(matched)
}

/// What a change does to the set it was planned against.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Steps {
	/// A record that is replaced: the index in `fresh` of the record to
	/// update in place, and what it becomes.
	pub updates: Vec<(usize, DnsRecord)>,
	/// A record that arrives and replaces none.
	pub creations: Vec<DnsRecord>,
	/// The index in `fresh` of a record that leaves.
	pub deletions: Vec<usize>,
}

/// The steps that turn the set of `change.before` into `change.after`.
/// `matched` is what [`held`] returned: the index in `fresh` of each record
/// of `before`.
pub(crate) fn steps(change: &Change, matched: &[usize]) -> Steps {
	// What stays is what the plan carried over unchanged; the rest of the
	// set that was read leaves, and the rest of the set to write arrives.
	let mut arriving: Vec<&DnsRecord> = change.after.iter().collect();
	let mut leaving: Vec<usize> = Vec::new();
	for (seen, &index) in change.before.iter().zip(matched) {
		match arriving.iter().position(|r| **r == seen.record) {
			Some(position) => {
				arriving.remove(position);
			}
			None => leaving.push(index),
		}
	}
	let replaced = leaving.len().min(arriving.len());
	let mut arriving = arriving.into_iter().cloned();
	let updates = leaving
		.iter()
		.zip(arriving.by_ref())
		.map(|(&index, record)| (index, record))
		.collect();
	Steps {
		updates,
		creations: arriving.collect(),
		deletions: leaving.split_off(replaced),
	}
}

/// A change that writes outside the name and type it declares is refused
/// before anything is read.
pub(crate) fn within_scope(change: &Change) -> Result<(), Stop> {
	let name = canonical_name(&change.name);
	if change
		.after
		.iter()
		.any(|r| r.kind != change.kind || canonical_name(&r.name) != name)
	{
		return Err(Stop::Refused(
			"the change writes outside the name and type it declares".into(),
		));
	}
	Ok(())
}

/// The requests of a provider that writes by id.
pub(crate) trait ById {
	/// A record as the provider's write requests take it.
	type Body: Send + Sync;

	/// Whether the credential may write at `name`.
	fn authorizes(&self, name: &str) -> bool;

	/// The records at the name and type of `change`, read again now.
	async fn read_set(&self, zone: &str, change: &Change) -> Result<Vec<Fresh>, ProviderError>;

	/// The request body of `record`; refused here, before any write, when the
	/// provider cannot take it.
	fn body(&self, record: &DnsRecord) -> Result<Self::Body, ProviderError>;

	/// Replace the record `id` in place.
	async fn update(&self, zone: &str, id: &str, body: &Self::Body) -> Result<(), ProviderError>;

	/// Create a record.
	async fn create(&self, zone: &str, body: &Self::Body) -> Result<(), ProviderError>;

	/// Delete the record `id`.
	async fn delete(&self, zone: &str, id: &str) -> Result<(), ProviderError>;

	/// What the provider needs once after the writes of a change for them to
	/// take effect (a zone that publishes on request). Not called when the
	/// change wrote nothing.
	async fn finish(&self, _zone: &str) -> Result<(), ProviderError> {
		Ok(())
	}
}

/// Whether a write went out, to tell a refusal from an unknown outcome.
struct Sent(bool);

impl Sent {
	fn record(&mut self, result: Result<(), ProviderError>) -> Result<(), Stop> {
		match result {
			Ok(()) => {
				self.0 = true;
				Ok(())
			}
			// A refused credential is a definite answer, as long as nothing
			// was written before it.
			Err(ProviderError::Auth) if !self.0 => {
				Err(Stop::Refused(ProviderError::Auth.to_string()))
			}
			Err(_) => Err(Stop::Unknown),
		}
	}
}

/// Check the precondition and apply `change`, or say why it did not go out.
async fn run<W: ById>(writer: &W, zone: &str, change: &Change) -> Result<(), Stop> {
	if !writer.authorizes(&change.name) {
		return Err(ProviderError::Auth.into());
	}
	within_scope(change)?;
	let fresh = writer.read_set(zone, change).await?;
	let matched = held(change, &fresh).ok_or(Stop::Changed)?;
	let steps = steps(change, &matched);
	let updates = steps
		.updates
		.iter()
		.map(|(index, record)| Ok((&fresh[*index].id, writer.body(record)?)))
		.collect::<Result<Vec<_>, ProviderError>>()?;
	let creations = steps
		.creations
		.iter()
		.map(|record| writer.body(record))
		.collect::<Result<Vec<_>, ProviderError>>()?;
	let mut sent = Sent(false);
	for (id, body) in &updates {
		sent.record(writer.update(zone, id, body).await)?;
	}
	for body in &creations {
		sent.record(writer.create(zone, body).await)?;
	}
	for &index in &steps.deletions {
		sent.record(writer.delete(zone, &fresh[index].id).await)?;
	}
	if sent.0 {
		sent.record(writer.finish(zone).await)?;
	}
	Ok(())
}

/// Apply `change` to `zone` under the deadline of an operation and say what
/// happened.
pub(crate) async fn apply<W: ById>(writer: &W, zone: &str, change: Change) -> Receipt {
	match crate::dns::providers::within(async { Ok(run(writer, zone, &change).await) }).await {
		Ok(Ok(())) => Receipt::Applied {
			identity: None,
			revision: None,
		},
		Ok(Err(Stop::Changed)) => Receipt::PreconditionFailed,
		Ok(Err(Stop::Refused(reason))) => Receipt::Rejected(reason),
		// The operation deadline ran out: a write may have gone out.
		Ok(Err(Stop::Unknown)) | Err(_) => Receipt::Unknown,
	}
}
