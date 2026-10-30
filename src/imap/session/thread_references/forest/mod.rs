//! The parent links of RFC 5256 §3 step 1, with the loop check it asks
//! for on every link.
//!
//! "Do not create a link if that link would introduce a loop": a link only
//! ever goes to a node without a parent, so it loops exactly when the new
//! parent already sits in that node's tree, that is when the root above
//! the new parent is the node itself. Walking up the parents to find that
//! root costs the depth of the tree, and a reply chain is as deep as the
//! mailbox is long, which makes the whole build quadratic. Step 1.B also
//! cuts links, so a union-find cannot answer it either. A link-cut tree
//! answers "root above x" under links and cuts in amortized O(log n), so
//! the build stays O(n log n) whatever the shape of the references.
//!
//! The splay tree operations are loops over index arrays: nothing here
//! recurses, so no input can exhaust the stack.

/// No node: the sentinel at index 0 of the link-cut arrays, and the
/// "no parent" value of [`Forest::parent`].
const NIL: u32 = 0;

/// Nodes numbered from 0, each with at most one parent, kept acyclic.
pub(super) struct Forest {
	/// `parent[x]` is the parent of node `x`, or [`NIL`]; parents are
	/// stored one up so that [`NIL`] is free to mean "none".
	parent: Vec<u32>,
	/// The link-cut tree over the same links, in one-up numbering.
	splay: Splay,
}

impl Forest {
	pub(super) fn new() -> Self {
		Self {
			parent: Vec::new(),
			splay: Splay::new(),
		}
	}

	/// Add a node without parent and return its number.
	pub(super) fn add(&mut self) -> u32 {
		self.parent.push(NIL);
		self.splay.push() - 1
	}

	pub(super) fn len(&self) -> usize {
		self.parent.len()
	}

	pub(super) fn parent(&self, node: u32) -> Option<u32> {
		let parent = self.parent[node as usize];
		(parent != NIL).then(|| parent - 1)
	}

	/// Make `parent` the parent of `child`, which must have none. Refused
	/// (false) when `parent` is `child` or a descendant of it.
	pub(super) fn link(&mut self, child: u32, parent: u32) -> bool {
		debug_assert!(self.parent(child).is_none());
		let (child_up, parent_up) = (child + 1, parent + 1);
		if self.splay.find_root(parent_up) == child_up {
			return false;
		}
		self.splay.link(child_up, parent_up);
		self.parent[child as usize] = parent_up;
		true
	}

	/// Remove the link to the parent of `child`, if it has one.
	pub(super) fn cut(&mut self, child: u32) {
		if self.parent(child).is_some() {
			self.splay.cut(child + 1);
			self.parent[child as usize] = NIL;
		}
	}
}

/// A link-cut tree without path reversal, in arrays. Index 0 is the
/// sentinel and is never written. `up[x]` is the splay parent of `x`, or,
/// when `x` is the root of its splay tree, the path-parent pointer to the
/// node above its preferred path. `kids[x]` are the splay children; a
/// splay tree keeps its path ordered from the root of the forest tree
/// (leftmost) down.
struct Splay {
	up: Vec<u32>,
	kids: Vec<[u32; 2]>,
}

impl Splay {
	fn new() -> Self {
		Self {
			up: vec![NIL],
			kids: vec![[NIL, NIL]],
		}
	}

	fn push(&mut self) -> u32 {
		self.up.push(NIL);
		self.kids.push([NIL, NIL]);
		(self.up.len() - 1) as u32
	}

	fn kid(&self, node: u32, side: usize) -> u32 {
		self.kids[node as usize][side]
	}

	/// Whether `node` is the root of its splay tree (its `up` is a
	/// path-parent pointer or nothing).
	fn is_splay_root(&self, node: u32) -> bool {
		let up = self.up[node as usize];
		self.kid(up, 0) != node && self.kid(up, 1) != node
	}

	fn side(&self, node: u32) -> usize {
		usize::from(self.kid(self.up[node as usize], 1) == node)
	}

	fn rotate(&mut self, node: u32) {
		let parent = self.up[node as usize];
		let grand = self.up[parent as usize];
		let side = self.side(node);
		if !self.is_splay_root(parent) {
			let parent_side = self.side(parent);
			self.kids[grand as usize][parent_side] = node;
		}
		self.up[node as usize] = grand;
		let moved = self.kid(node, side ^ 1);
		self.kids[parent as usize][side] = moved;
		if moved != NIL {
			self.up[moved as usize] = parent;
		}
		self.kids[node as usize][side ^ 1] = parent;
		self.up[parent as usize] = node;
	}

	fn splay(&mut self, node: u32) {
		while !self.is_splay_root(node) {
			let parent = self.up[node as usize];
			if !self.is_splay_root(parent) {
				let zig_zig = self.side(node) == self.side(parent);
				self.rotate(if zig_zig { parent } else { node });
			}
			self.rotate(node);
		}
	}

	/// Make the path from the forest root to `node` preferred, ending at
	/// `node`, and splay `node` to the root of that path's splay tree.
	fn access(&mut self, node: u32) {
		let mut below = NIL;
		let mut at = node;
		while at != NIL {
			self.splay(at);
			self.kids[at as usize][1] = below;
			below = at;
			at = self.up[at as usize];
		}
		self.splay(node);
	}

	fn find_root(&mut self, node: u32) -> u32 {
		self.access(node);
		let mut root = node;
		while self.kid(root, 0) != NIL {
			root = self.kid(root, 0);
		}
		self.splay(root);
		root
	}

	/// Hang `child`, the root of its forest tree, under `parent`.
	fn link(&mut self, child: u32, parent: u32) {
		self.access(child);
		self.up[child as usize] = parent;
	}

	fn cut(&mut self, child: u32) {
		self.access(child);
		let above = self.kid(child, 0);
		if above != NIL {
			self.up[above as usize] = NIL;
			self.kids[child as usize][0] = NIL;
		}
	}
}

#[cfg(test)]
mod tests;
