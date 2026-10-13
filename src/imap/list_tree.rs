//! Which names a LIST or LSUB returns over the mailbox hierarchy (RFC 9051
//! §6.3.9, RFC 5258 §3).
//!
//! A name is returned when it matches a pattern and meets the selection
//! criteria. A name that matches but does not meet them can still be
//! returned for a descendant that meets them and does not match the pattern
//! itself (`a` for a subscribed `a/b` under `LSUB "" %`): as a `\Noselect`
//! placeholder, with `CHILDINFO` under `RECURSIVEMATCH`, or not at all.
//!
//! The work is linear in the number of names times the hierarchy depth
//! (bounded by [`crate::util::mailbox_path::MAX_DEPTH`]): every name is
//! visited once, and each walks up its own ancestors once.

use std::collections::{BTreeSet, HashSet};

use crate::util::mailbox_path;

/// What to do with a matching name that only stands for hidden descendants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Hidden {
	/// Leave it out (a selection option without `RECURSIVEMATCH`).
	Skip,
	/// Return it with the `CHILDINFO` extended data (`RECURSIVEMATCH`).
	ChildInfo,
	/// Return it as a placeholder that cannot be selected (plain LIST, LSUB).
	Placeholder,
}

/// One name to return.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entry<'a> {
	/// The stored name.
	pub name: &'a str,
	/// Whether a mailbox of this name exists.
	pub exists: bool,
	/// Whether an existing mailbox lies below it.
	pub has_children: bool,
	/// Returned only for its descendants, as a `\Noselect` placeholder.
	pub placeholder: bool,
	/// Returned only for its descendants, with `CHILDINFO`.
	pub child_info: bool,
}

/// The names to return, `INBOX` first and the rest sorted.
///
/// `existing` are the mailboxes that exist; `extra` are further candidates
/// that may not exist (the subscriptions, for a `SUBSCRIBED` selection or for
/// LSUB). `qualifies(name, exists)` is the selection criteria and
/// `matches(name)` the patterns.
pub(crate) fn select<'a>(
	existing: &'a [String],
	extra: &'a [String],
	qualifies: impl Fn(&str, bool) -> bool,
	matches: impl Fn(&str) -> bool,
	hidden: Hidden,
) -> Vec<Entry<'a>> {
	let exists: HashSet<&str> = existing.iter().map(String::as_str).collect();
	let parents: HashSet<&str> = existing
		.iter()
		.flat_map(|name| mailbox_path::ancestors(name))
		.collect();
	let candidates: BTreeSet<&str> = existing.iter().chain(extra).map(String::as_str).collect();
	let mut qualified = HashSet::new();
	let mut standing_in: HashSet<&str> = HashSet::new();
	for &name in &candidates {
		if qualifies(name, exists.contains(name)) {
			qualified.insert(name);
			if hidden != Hidden::Skip && !matches(name) {
				standing_in.extend(mailbox_path::ancestors(name));
			}
		}
	}
	let mut all = candidates;
	all.extend(standing_in.iter().copied());
	let mut names: Vec<&str> = all.into_iter().collect();
	if let Some(at) = names.iter().position(|name| *name == "INBOX") {
		names[..=at].rotate_right(1);
	}
	names
		.into_iter()
		.filter(|name| matches(name))
		.filter_map(|name| {
			let selected = qualified.contains(name);
			if !selected && !standing_in.contains(name) {
				return None;
			}
			Some(Entry {
				name,
				exists: exists.contains(name),
				has_children: parents.contains(name),
				placeholder: !selected && hidden == Hidden::Placeholder,
				child_info: !selected && hidden == Hidden::ChildInfo,
			})
		})
		.collect()
}

#[cfg(test)]
#[path = "list_tree_tests.rs"]
mod tests;
