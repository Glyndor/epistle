//! RFC 5256 §3 steps 4 to 6: order the threads, merge the ones that share a
//! base subject, then order every set of siblings.

use std::collections::HashMap;

use super::{Message, Tree};

/// A top-level slot whose thread was merged into another one.
const MERGED: u32 = u32::MAX;

/// Steps 4 to 6 over the pruned `tree` of `messages`.
pub(super) fn gather(tree: &mut Tree, messages: &[Message]) {
	// (4) The top level by sent date, a dummy by its first child.
	for &root in &tree.roots {
		if tree.is_dummy(root) {
			sort_siblings(&mut tree.children[root as usize], messages);
		}
	}
	let mut roots = std::mem::take(&mut tree.roots);
	roots.sort_unstable_by_key(|&root| sort_key(tree, messages, root));
	merge_subjects(tree, messages, &mut roots);
	tree.roots = roots.into_iter().filter(|&root| root != MERGED).collect();
	// (6) Every set of siblings. A dummy only ever holds messages, so its
	// first child is known once the children are sorted, and the top
	// level comes last.
	for children in &mut tree.children {
		sort_siblings(children, messages);
	}
	let mut roots = std::mem::take(&mut tree.roots);
	roots.sort_unstable_by_key(|&root| sort_key(tree, messages, root));
	tree.roots = roots;
}

/// (5) Merge the top-level threads with the same base subject. A merged
/// slot is set to [`MERGED`]; a slot whose thread gains a new dummy
/// parent holds that dummy.
fn merge_subjects(tree: &mut Tree, messages: &[Message], roots: &mut [u32]) {
	let subject = |tree: &Tree, node: u32| messages[tree.first_message(node) as usize].subject;
	let reply = |node: u32| messages[node as usize].reply;
	// (B) One slot per subject: a dummy over a message, and an original
	// over a reply or forward.
	let mut table: HashMap<[u8; 16], usize> = HashMap::new();
	for (slot, &node) in roots.iter().enumerate() {
		let Some(key) = subject(tree, node) else {
			continue;
		};
		let held = *table.entry(key).or_insert(slot);
		let current = roots[held];
		if !tree.is_dummy(current) && (tree.is_dummy(node) || (reply(current) && !reply(node))) {
			table.insert(key, slot);
		}
	}
	// (C) Merge every other thread into the one in the table.
	for slot in 0..roots.len() {
		let node = roots[slot];
		let Some(key) = subject(tree, node) else {
			continue;
		};
		let held = table[&key];
		if held == slot {
			continue;
		}
		let kept = roots[held];
		roots[slot] = MERGED;
		// Messages that join a dummy: the current one, or a dummy's
		// children (a dummy never goes under another dummy).
		let joining = if tree.is_dummy(node) {
			std::mem::take(&mut tree.children[node as usize])
		} else {
			vec![node]
		};
		if tree.is_dummy(kept) {
			tree.children[kept as usize].extend(joining);
		} else if !tree.is_dummy(node) && reply(node) && !reply(kept) {
			tree.children[kept as usize].push(node);
		} else {
			let mut members = vec![kept];
			members.extend(joining);
			roots[held] = tree.dummy(members);
		}
	}
}

/// What RFC 5256 §2.2 orders by: the sent date, then the sequence number.
/// A dummy sorts as its first child.
fn sort_key(tree: &Tree, messages: &[Message], node: u32) -> (i64, u32) {
	let message = &messages[tree.first_message(node) as usize];
	(message.sent, message.seqno)
}

fn sort_siblings(children: &mut [u32], messages: &[Message]) {
	children.sort_unstable_by_key(|&child| {
		let message = &messages[child as usize];
		(message.sent, message.seqno)
	});
}
