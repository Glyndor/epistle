//! RFC 5256 §3 steps 1 to 3: link the messages by their references, then
//! drop the dummies.

use std::collections::HashMap;

use super::Tree;
use super::forest::Forest;
use super::msgid::Key;

/// A container that holds no message (a dummy).
const DUMMY: u32 = u32::MAX;

/// The containers of step 1: one per Message ID seen, plus one per message
/// whose id is missing, invalid or a duplicate.
pub(super) struct Builder {
	/// The container of every Message ID seen, as a message's own id or
	/// as a reference.
	ids: HashMap<Key, u32>,
	/// For each container, the index of the message it holds, or [`DUMMY`].
	holds: Vec<u32>,
	forest: Forest,
}

impl Builder {
	pub(super) fn new() -> Self {
		Self {
			ids: HashMap::new(),
			holds: Vec::new(),
			forest: Forest::new(),
		}
	}

	/// How many containers step 1 has made so far.
	#[cfg(test)]
	pub(super) fn containers(&self) -> usize {
		self.holds.len()
	}

	fn create(&mut self, holds: u32) -> u32 {
		self.holds.push(holds);
		self.forest.add()
	}

	/// The container for `key`, a new dummy when the id was never seen.
	fn container(&mut self, key: Key) -> u32 {
		if let Some(&found) = self.ids.get(&key) {
			return found;
		}
		let created = self.create(DUMMY);
		self.ids.insert(key, created);
		created
	}

	/// Step 1 for message number `index` (messages are added in sequence
	/// order). `id` is its Message ID, `references` its references.
	pub(super) fn add(&mut self, index: u32, id: Option<Key>, references: &[Key]) {
		// The message's own container. Only the first message with an id
		// uses it; a missing or duplicate id gets a container no
		// reference can name, which is what a unique id amounts to.
		let own = match id.map(|key| (key, self.ids.get(&key).copied())) {
			Some((_, Some(found))) if self.holds[found as usize] == DUMMY => {
				self.holds[found as usize] = index;
				found
			}
			Some((key, None)) => {
				let created = self.create(index);
				self.ids.insert(key, created);
				created
			}
			_ => self.create(index),
		};
		// (A) Each reference is the parent of the next one, unless the
		// next one already has a parent or the link would loop.
		let mut previous = None;
		for &key in references {
			let current = self.container(key);
			if let Some(parent) = previous
				&& self.forest.parent(current).is_none()
			{
				self.forest.link(current, parent);
			}
			previous = Some(current);
		}
		// (B) The last reference is the parent of the message, replacing
		// any parent step (A) of an earlier message gave it, unless that
		// would loop. With no references the message has no parent.
		self.forest.cut(own);
		if let Some(parent) = previous {
			self.forest.link(own, parent);
		}
	}

	/// Steps 2 and 3 for `messages` messages: the threads under the root,
	/// with every dummy gone except one at the top that holds two or more
	/// messages. A message hangs under its nearest ancestor that holds a
	/// message; one with no such ancestor goes to the top, or into the
	/// dummy at the top of its tree when that dummy keeps several.
	pub(super) fn prune(self, messages: usize) -> Tree {
		let total = self.forest.len();
		let parent = |node: usize| self.forest.parent(node as u32).map(|p| p as usize);
		// The children of every container, as one array cut into slices
		// (`kids[start[c]..start[c + 1]]`), so no container allocates.
		let mut start = vec![0usize; total + 1];
		for node in 0..total {
			if let Some(up) = parent(node) {
				start[up + 1] += 1;
			}
		}
		for node in 0..total {
			start[node + 1] += start[node];
		}
		let mut fill = start.clone();
		let mut kids = vec![0u32; start[total]];
		for node in 0..total {
			if let Some(up) = parent(node) {
				kids[fill[up]] = node as u32;
				fill[up] += 1;
			}
		}
		// From the roots down, with an explicit stack: the tree root of
		// every container and its nearest ancestor holding a message.
		let mut top = vec![0u32; total];
		let mut anchor = vec![DUMMY; total];
		let mut stack: Vec<usize> = (0..total).filter(|&n| parent(n).is_none()).collect();
		for &root in &stack {
			top[root] = root as u32;
		}
		while let Some(node) = stack.pop() {
			let inherited = match self.holds[node] {
				DUMMY => anchor[node],
				held => held,
			};
			for &kid in &kids[start[node]..start[node + 1]] {
				top[kid as usize] = top[node];
				anchor[kid as usize] = inherited;
				stack.push(kid as usize);
			}
		}
		let mut tree = Tree::new(messages);
		let mut groups: HashMap<u32, usize> = HashMap::new();
		let mut grouped: Vec<Vec<u32>> = Vec::new();
		for node in 0..total {
			let held = self.holds[node];
			if held == DUMMY {
				continue;
			}
			if anchor[node] != DUMMY {
				tree.children[anchor[node] as usize].push(held);
			} else if parent(node).is_none() {
				tree.roots.push(held);
			} else {
				let slot = *groups.entry(top[node]).or_insert_with(|| {
					grouped.push(Vec::new());
					grouped.len() - 1
				});
				grouped[slot].push(held);
			}
		}
		for members in grouped {
			match members.as_slice() {
				[only] => tree.roots.push(*only),
				_ => {
					let dummy = tree.dummy(members);
					tree.roots.push(dummy);
				}
			}
		}
		tree
	}
}
