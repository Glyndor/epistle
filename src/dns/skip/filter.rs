//! The one filter that decides what epistle publishes.
//!
//! The wanted record set is computed once, in
//! [`crate::dns::desired`], and filtered here: the reconcile loop and
//! `epistle dns publish` read the same filtered set, so a record the
//! configuration skips is never published by one of them and published by
//! the other.
//!
//! The filter only takes records out of the set. A record that epistle
//! published earlier stays in the ledger, and the publisher retires it
//! through the ledger like a record the configuration no longer needs.

use crate::dns::records::PublishRecord;

use super::{SkipGroup, SkipSet, SkippedGroup, group_of_check};

/// Split the wanted records into the ones to publish and the ones the
/// configuration skips. The skipped ones keep their group, so the operator
/// sees what is left out and why.
pub fn split_records(
	records: Vec<PublishRecord>,
	skip: &SkipSet,
) -> (Vec<PublishRecord>, Vec<SkippedGroup>) {
	let mut kept = Vec::new();
	let mut skipped: Vec<SkippedGroup> = Vec::new();
	for record in records {
		match skip.group_of(&record.record) {
			Some(group) => match skipped.iter_mut().find(|entry| entry.group == group) {
				Some(entry) => entry.records.push(record),
				None => skipped.push(SkippedGroup {
					group,
					records: vec![record],
				}),
			},
			None => kept.push(record),
		}
	}
	(kept, sort_groups(skipped))
}

/// The skipped groups in the order of [`SkipGroup::ALL`], so the operator
/// reads the same order every run.
fn sort_groups(mut groups: Vec<SkippedGroup>) -> Vec<SkippedGroup> {
	groups.sort_by_key(|entry| {
		SkipGroup::ALL
			.iter()
			.position(|group| *group == entry.group)
			.unwrap_or(usize::MAX)
	});
	groups
}

/// Mark the checks that belong to a group the configuration skips. A record
/// the operator does not want published is not a record that is missing.
pub fn split_checks(checks: Vec<crate::dns::Check>, skip: &SkipSet) -> Vec<crate::dns::Check> {
	checks
		.into_iter()
		.map(|mut check| {
			if let Some(group) = group_of_check(&check.kind, &check.name)
				&& skip.skips(group, &check.name)
			{
				check.mark_skipped(group);
			}
			check
		})
		.collect()
}
