//! Compare a zone with the records the configuration needs, and plan the
//! difference.
//!
//! The plan is pure: it reads the zone listing, the records the
//! configuration needs ([`crate::dns::desired`]) and the [`Ledger`] of what
//! epistle published there before, and it writes nothing. Each needed record
//! ends in one entry and so does each ledger record the configuration no
//! longer needs:
//!
//! - missing: [`Action::Create`];
//! - present with the needed value: [`Action::Present`] when epistle wrote
//!   it, [`Action::Adopted`] when somebody else did (it is left alone and
//!   not claimed);
//! - present with another value that epistle wrote: [`Action::Update`];
//! - present with another value that epistle did not write, or sharing the
//!   slot with such a record: [`Action::Conflict`], left as is;
//! - a DMARC record at least as strict as the needed one, whoever wrote it:
//!   [`Action::Kept`];
//! - epistle's own record that the configuration no longer needs:
//!   [`Action::Remove`], and [`Action::Gone`] when it already left the zone;
//! - a name below a delegation, a name that is not valid, or a DKIM key the
//!   rotation retires: [`Action::Skipped`].
//!
//! A difference in TTL or in the description a provider stores is not a
//! difference: rewriting a record for its label would gain nothing and a
//! provider that deletes and recreates it opens a moment where the name does
//! not resolve.

use std::collections::BTreeSet;

use serde::Serialize;

use crate::dns::names::{canonical_name, in_domain, is_valid_name};
use crate::dns::provider::{DnsRecord, RecordKind, txt_purpose};
use crate::dns::rrset::{Cuts, same_record};

pub mod apply;
mod dmarc;
mod ledger;
pub mod once;
mod remove;
mod slot;
pub mod store;
pub mod survey;
pub mod undo;

pub use ledger::{Ledger, LedgerEntry};
use slot::{Owners, is_dkim, same_slot, slot_of, values, whole_set};

/// What a plan does with one record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
	/// The record is missing and is written.
	Create,
	/// Epistle's own record has another value and is rewritten.
	Update,
	/// Epistle's own record is no longer needed and is removed.
	Remove,
	/// The record is there as needed, written by epistle.
	Present,
	/// The record is there as needed, written by somebody else. Left alone.
	Adopted,
	/// A record somebody else wrote is in the way. Left as is.
	Conflict,
	/// The record in place differs and stays: a DMARC policy at least as
	/// strict as the needed one.
	Kept,
	/// Epistle's own record already left the zone; the ledger forgets it.
	Gone,
	/// Not planned: the reason says why.
	Skipped,
}

impl Action {
	/// Whether the action writes to the zone.
	pub fn writes(self) -> bool {
		matches!(self, Action::Create | Action::Update | Action::Remove)
	}
}

/// One record of the plan, and what is done with it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Entry {
	/// What the plan does.
	pub action: Action,
	/// The record to write, or the one to remove.
	pub record: DnsRecord,
	/// Why, for the operator.
	pub reason: String,
	/// The values in the slot now, when they matter for the decision.
	#[serde(skip_serializing_if = "Vec::is_empty")]
	pub current: Vec<String>,
}

/// The plan for one zone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ZonePlan {
	/// The zone, in canonical form.
	pub zone: String,
	/// One entry per needed record, then one per ledger record no longer
	/// needed.
	pub entries: Vec<Entry>,
}

impl ZonePlan {
	/// How many entries write to the zone.
	pub fn writes(&self) -> usize {
		self.entries.iter().filter(|e| e.action.writes()).count()
	}

	/// Whether applying the plan changes the zone or the ledger.
	pub fn changes(&self) -> bool {
		self.entries
			.iter()
			.any(|e| e.action.writes() || e.action == Action::Gone)
	}
}

/// Everything [`plan_zone`] reads.
pub struct ZoneInput<'a> {
	/// The zone the provider listed.
	pub zone: &'a str,
	/// The records the configuration needs in this zone.
	pub needed: &'a [DnsRecord],
	/// Every record the provider listed for the zone.
	pub existing: &'a [DnsRecord],
	/// What epistle published in this zone before.
	pub ledger: &'a Ledger,
	/// Records another part of epistle published and remembers (the TLSA
	/// values of the certificate refresh): they count as epistle's own.
	pub also_ours: &'a [DnsRecord],
	/// Records `dns lockdown` published (its journal). It moves them on its
	/// own schedule, the DMARC policy one step per run, so a slot that holds
	/// one is left as it is.
	pub lockdown: &'a [DnsRecord],
	/// Retire only ledger records at or under this domain; `None` retires
	/// anywhere in the zone.
	pub retire_within: Option<&'a str>,
	/// Why the needed set is incomplete this run, when it is: an input that
	/// could not be read (a DKIM key, the certificate) leaves records out of
	/// `needed`, and a record left out is not a record no longer needed. With
	/// a reason here nothing is removed; the plan says why.
	pub incomplete: Option<&'a str>,
}

/// Plan `input`. Pure: nothing is read or written outside `input`.
pub fn plan_zone(input: &ZoneInput<'_>) -> ZonePlan {
	let zone = canonical_name(input.zone);
	let cuts = Cuts::new(&zone, input.existing);
	let ledger = input.ledger.records();
	let owners = Owners {
		ledger: &ledger,
		also: input.also_ours,
	};
	let mut entries = Vec::new();
	for group in slots(input.needed) {
		plan_slot(&group, input, &cuts, &owners, &mut entries);
	}
	for held in &input.ledger.entries {
		let record = &held.record;
		let name = canonical_name(&record.name);
		if input.retire_within.is_some_and(|d| !in_domain(&name, d))
			|| input.needed.iter().any(|n| same_slot(n, record))
		{
			continue;
		}
		let mut entry = retire(record, input.existing, &cuts);
		if entry.action == Action::Remove
			&& let Some(why) = input.incomplete
		{
			entry.action = Action::Skipped;
			entry.reason = format!(
				"{name} {} is not removed this run: the needed set is incomplete ({why})",
				record.kind.as_str()
			);
		}
		entries.push(entry);
	}
	ZonePlan { zone, entries }
}

/// The needed records grouped by slot, in the order they were given.
fn slots(needed: &[DnsRecord]) -> Vec<Vec<&DnsRecord>> {
	let mut groups: Vec<Vec<&DnsRecord>> = Vec::new();
	for record in needed {
		match groups.iter_mut().find(|g| same_slot(g[0], record)) {
			Some(group) => group.push(record),
			None => groups.push(vec![record]),
		}
	}
	groups
}

fn entry(action: Action, record: &DnsRecord, reason: String, current: Vec<String>) -> Entry {
	Entry {
		action,
		record: record.clone(),
		reason,
		current,
	}
}

/// A text read from a zone, escaped before it reaches a terminal, a message
/// or the server log.
///
/// The value of a record in a zone is text from outside: a control
/// character in it could move the cursor, repaint the terminal or add a
/// line to the log the operator reads.
pub(super) fn from_zone(text: &str) -> String {
	crate::cli::term::sanitize(text)
}

/// Plan the needed records of one slot.
fn plan_slot(
	group: &[&DnsRecord],
	input: &ZoneInput<'_>,
	cuts: &Cuts,
	owners: &Owners<'_>,
	entries: &mut Vec<Entry>,
) {
	let existing = input.existing;
	let first = group[0];
	let name = canonical_name(&first.name);
	let kind = first.kind.as_str();
	let all = |action, reason: String, current: Vec<String>| {
		group
			.iter()
			.map(move |r| entry(action, r, reason.clone(), current.clone()))
			.collect::<Vec<_>>()
	};
	if !is_valid_name(&name) {
		entries.extend(all(
			Action::Skipped,
			format!("{name} is not a valid DNS name; left as is"),
			vec![],
		));
		return;
	}
	if let Some(cut) = cuts.above(&name) {
		entries.extend(all(
			Action::Skipped,
			format!(
				"{} is delegated to other nameservers; nothing is written under it",
				from_zone(cut)
			),
			vec![],
		));
		return;
	}
	if let Some(reason) = cname_clash(first, &name, existing) {
		entries.extend(all(Action::Conflict, reason, vec![]));
		return;
	}
	let slot = slot_of(first, existing);
	let current = values(&slot);
	let tagged = first.kind == RecordKind::Txt && txt_purpose(&first.value).is_some();
	if tagged && slot.len() > 1 {
		let purpose = txt_purpose(&first.value).unwrap_or_default();
		entries.extend(all(
			Action::Conflict,
			format!(
				"{name} holds {} {purpose} records; receivers ignore every one of them, so keep one by hand",
				slot.len()
			),
			current,
		));
		return;
	}
	let present = |r: &DnsRecord| slot.iter().any(|s| same_record(s, r));
	if group.iter().all(|r| present(r)) {
		for record in group {
			let (action, reason) = if owners.owns(record) {
				(
					Action::Present,
					format!("{name} {kind} is published as needed"),
				)
			} else {
				(
					Action::Adopted,
					format!("{name} {kind} is already there as needed; left as is"),
				)
			};
			entries.push(entry(action, record, reason, vec![]));
		}
		return;
	}
	if group.len() > 1 {
		entries.extend(all(
			Action::Conflict,
			format!(
				"{name} needs {} {kind} values in one set and a provider write replaces the set with one; add them by hand",
				group.len()
			),
			current,
		));
		return;
	}
	if slot
		.iter()
		.any(|r| input.lockdown.iter().any(|l| same_record(l, r)))
	{
		entries.extend(all(
			Action::Kept,
			format!(
				"{name} {kind} was published by dns lockdown, which moves it on its own; left as is"
			),
			current,
		));
		return;
	}
	if slot.is_empty() {
		let what = txt_purpose(&first.value).filter(|_| tagged).unwrap_or(kind);
		entries.push(entry(
			Action::Create,
			first,
			format!("{name} has no {what} record"),
			vec![],
		));
		return;
	}
	if tagged && txt_purpose(&first.value) == Some("v=DMARC1") {
		entries.push(plan_dmarc(first, slot[0], owners, current));
		return;
	}
	let foreign: Vec<&DnsRecord> = slot.iter().copied().filter(|r| !owners.owns(r)).collect();
	if foreign.is_empty() {
		entries.push(entry(
			Action::Update,
			first,
			format!("{name} {kind} was published by epistle with another value"),
			current,
		));
	} else {
		entries.push(entry(
			Action::Conflict,
			first,
			format!(
				"{name} holds {kind} records epistle did not publish ({}); left as is",
				values(&foreign)
					.iter()
					.map(|value| from_zone(value))
					.collect::<Vec<_>>()
					.join("; ")
			),
			current,
		));
	}
}

/// A CNAME may not share its name with any other record (RFC 1034 section
/// 3.6.2), so a needed CNAME at a name with other records, or a needed record
/// at a name that is a CNAME, is a conflict.
fn cname_clash(needed: &DnsRecord, name: &str, existing: &[DnsRecord]) -> Option<String> {
	let at_name: Vec<&DnsRecord> = existing
		.iter()
		.filter(|r| canonical_name(&r.name) == name)
		.collect();
	if needed.kind == RecordKind::Cname {
		let others: BTreeSet<&str> = at_name
			.iter()
			.filter(|r| r.kind != RecordKind::Cname)
			.map(|r| r.kind.as_str())
			.collect();
		return (!others.is_empty()).then(|| {
			format!(
				"{name} has {} records and a CNAME may not sit next to other records; left as is",
				others.into_iter().collect::<Vec<_>>().join(", ")
			)
		});
	}
	at_name
		.iter()
		.find(|r| r.kind == RecordKind::Cname)
		.map(|cname| {
			format!(
				"{name} is a CNAME to {} and no other record may sit next to it; left as is",
				from_zone(&cname.value)
			)
		})
}

/// The DMARC record in place is never replaced by a weaker one.
fn plan_dmarc(
	needed: &DnsRecord,
	in_place: &DnsRecord,
	owners: &Owners<'_>,
	current: Vec<String>,
) -> Entry {
	let name = canonical_name(&needed.name);
	match dmarc::compare(&in_place.value, &needed.value) {
		dmarc::Strength::AtLeast => entry(
			Action::Kept,
			needed,
			format!("{name} has a DMARC record at least as strict as this one; left as is"),
			current,
		),
		dmarc::Strength::Unreadable(why) => entry(
			Action::Conflict,
			needed,
			format!(
				"{name} has a DMARC record that cannot be read ({}); left as is",
				from_zone(&why)
			),
			current,
		),
		dmarc::Strength::Weaker(why) if owners.owns(in_place) => entry(
			Action::Update,
			needed,
			format!("{name} DMARC was published by epistle and {why}"),
			current,
		),
		dmarc::Strength::Weaker(why) => entry(
			Action::Conflict,
			needed,
			format!(
				"{name} has a DMARC record epistle did not publish and {why}; left as is, replace it by hand"
			),
			current,
		),
	}
}

/// Plan a ledger record the configuration no longer needs.
fn retire(record: &DnsRecord, existing: &[DnsRecord], cuts: &Cuts) -> Entry {
	let name = canonical_name(&record.name);
	let kind = record.kind.as_str();
	if !existing.iter().any(|r| same_record(r, record)) {
		return entry(
			Action::Gone,
			record,
			format!("{name} {kind} is no longer in the zone; the ledger forgets it"),
			vec![],
		);
	}
	if let Some(cut) = cuts.above(&name) {
		return entry(
			Action::Skipped,
			record,
			format!(
				"{} is delegated to other nameservers now; left as is",
				from_zone(cut)
			),
			vec![],
		);
	}
	if is_dkim(record) {
		return entry(
			Action::Skipped,
			record,
			format!("{name} is a DKIM key; the key rotation retires it, not the publisher"),
			vec![],
		);
	}
	let slot = slot_of(record, existing);
	if slot.len() == 1 {
		return entry(
			Action::Remove,
			record,
			format!(
				"{name} {kind} was published by epistle and the configuration no longer needs it"
			),
			vec![],
		);
	}
	let what = if whole_set(record) {
		"a provider delete removes the whole set"
	} else {
		"another record has the same purpose there"
	};
	entry(
		Action::Conflict,
		record,
		format!("{name} {kind} is no longer needed but {what}; left as is"),
		values(&slot),
	)
}

#[cfg(test)]
mod tests;
