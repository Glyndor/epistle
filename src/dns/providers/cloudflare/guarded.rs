//! The guarded write of a Cloudflare zone.
//!
//! Cloudflare gives a record an id and offers no revision of a zone and no
//! condition on a write (no ETag, no `If-Match`), so the precondition is the
//! one the provider can check: the set at the name and type is read again
//! right before the write and must still be the one the plan was made
//! against, with the same ids and the same values. The check and the write
//! are two requests, so a record another account changes in between is not
//! detected; what the write does is bounded all the same, because it
//! addresses records by id: a record the plan did not list is never updated
//! or deleted, and a record added in between stays.
//!
//! The change is applied as the difference between the set that was read and
//! the set to write: a record that stays is not touched, a record that is
//! replaced is updated in place by its id, a new one is created and one that
//! leaves is deleted by its id.

use super::list::record_of;
use super::*;
use crate::dns::names::canonical_name;
use crate::dns::publish::provider::{
	Change, Guard, ObservedRecord, Precondition, Receipt, Snapshot,
};
use crate::dns::rrset::same_record;

/// Why a change did not go out as a whole.
enum Stop {
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

/// The entries of `fresh` that stand for the records of `change.before`, in
/// the order of `before`, when the set is still the one the plan saw: the
/// same number of records, each with the id the snapshot gave it (when it
/// gave one) and its value.
fn held(change: &Change, fresh: &[RecordRef]) -> Option<Vec<usize>> {
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
				&& same_record(&seen.record, &record_of(now))
		})?;
		used[index] = true;
		matched.push(index);
	}
	Some(matched)
}

impl CloudflareProvider {
	/// The zone as Cloudflare lists it, each record with its id.
	pub(super) async fn snapshot_inner(&self, zone: &str) -> Result<Snapshot, ProviderError> {
		let zone_id = self.zone_id(zone).await?;
		let listed = self.list_refs(&zone_id, zone).await?;
		if listed.len() > crate::dns::providers::LIST_MAX_RECORDS {
			return Err(crate::dns::providers::listing_too_long(zone));
		}
		Ok(Snapshot {
			zone: zone.to_string(),
			records: listed
				.iter()
				.map(|r| ObservedRecord {
					record: record_of(r),
					identity: Some(r.id.clone()),
				})
				.collect(),
			revision: None,
			guard: Guard::Checked,
		})
	}

	pub(super) async fn apply_guarded_inner(&self, zone: &str, change: Change) -> Receipt {
		match crate::dns::providers::within(async { Ok(self.guarded_steps(zone, &change).await) })
			.await
		{
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

	async fn guarded_steps(&self, zone: &str, change: &Change) -> Result<(), Stop> {
		let kind = Self::api_kind(&change.kind)?;
		if !self.secret.authorizes(&change.name) {
			return Err(ProviderError::Auth.into());
		}
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
		let zone_id = self.zone_id(zone).await?;
		let fresh = self.find_records(&zone_id, &change.name, kind).await?;
		let matched = held(change, &fresh).ok_or(Stop::Changed)?;
		// What stays is what the plan carried over unchanged; the rest of
		// the set that was read leaves, and the rest of the set to write
		// arrives.
		let mut arriving: Vec<&DnsRecord> = change.after.iter().collect();
		let mut leaving: Vec<&RecordRef> = Vec::new();
		for (seen, &index) in change.before.iter().zip(&matched) {
			match arriving.iter().position(|r| **r == seen.record) {
				Some(position) => {
					arriving.remove(position);
				}
				None => leaving.push(&fresh[index]),
			}
		}
		let bodies = arriving
			.iter()
			.map(|record| Self::record_value(kind, record))
			.collect::<Result<Vec<_>, _>>()?;
		let mut bodies = bodies.into_iter();
		let mut wrote = false;
		let sent = |result: Result<(), ProviderError>, wrote: &mut bool| match result {
			Ok(()) => {
				*wrote = true;
				Ok(())
			}
			// A refused credential is a definite answer.
			Err(ProviderError::Auth) if !*wrote => {
				Err(Stop::Refused(ProviderError::Auth.to_string()))
			}
			Err(_) => Err(Stop::Unknown),
		};
		// A record that is replaced is updated in place by its id; the
		// others are created and the ones left over are deleted. The
		// updates and the creations go first, so the name is never left
		// without a record while the change is applied.
		let mut leaving = leaving.into_iter();
		for body in bodies.by_ref().take(leaving.len()) {
			let Some(old) = leaving.next() else { break };
			sent(
				self.write_record(&zone_id, Some(old), &body).await,
				&mut wrote,
			)?;
		}
		for body in bodies {
			sent(self.write_record(&zone_id, None, &body).await, &mut wrote)?;
		}
		for old in leaving {
			sent(self.delete_id(&zone_id, &old.id).await, &mut wrote)?;
		}
		Ok(())
	}
}
