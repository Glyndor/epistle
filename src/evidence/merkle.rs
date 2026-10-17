//! The Merkle tree over one day of records (RFC 6962 section 2.1).
//!
//! Leaf `i` is `SHA-256(0x00 || h_i)` where `h_i` is the SHA-256 of the
//! `i`-th line of the day, and an interior node is `SHA-256(0x01 || left ||
//! right)`, the domain separation RFC 6962 uses so that a leaf can never be
//! passed off as a node. The root of a day is computed while the day is
//! read, holding one hash per level, and inclusion proofs for any set of
//! records come out of one more pass, holding only the hashes the proofs
//! need. Neither ever holds the day.

use std::collections::{BTreeMap, HashSet};

use super::record::sha256;

/// The root of a day with no records (RFC 6962: the hash of the empty
/// string).
pub fn empty_root() -> [u8; 32] {
	sha256(b"")
}

/// The leaf for the record whose line hashes to `record_hash`.
pub fn leaf_hash(record_hash: &[u8; 32]) -> [u8; 32] {
	let mut input = [0u8; 33];
	input[1..].copy_from_slice(record_hash);
	sha256(&input)
}

/// The interior node over `left` and `right`.
pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
	let mut input = [0u8; 65];
	input[0] = 1;
	input[1..33].copy_from_slice(left);
	input[33..].copy_from_slice(right);
	sha256(&input)
}

/// One complete subtree on the stack: the leaves `[start, start + size)`.
#[derive(Debug, Clone, Copy)]
struct Subtree {
	start: u64,
	size: u64,
	hash: [u8; 32],
}

/// Builds the root from the leaves in order, in `O(log n)` memory, and
/// records along the way the subtree hashes a set of proofs needs.
#[derive(Debug, Default)]
pub struct TreeBuilder {
	stack: Vec<Subtree>,
	count: u64,
	wanted: HashSet<(u64, u64)>,
	found: BTreeMap<(u64, u64), [u8; 32]>,
}

impl TreeBuilder {
	/// A builder that only computes the root.
	pub fn new() -> Self {
		Self::default()
	}

	/// A builder that also keeps what the inclusion proofs of `targets`
	/// need, in a tree of `size` leaves.
	pub fn for_proofs(size: u64, targets: &[u64]) -> Self {
		let wanted = targets
			.iter()
			.filter(|target| **target < size)
			.flat_map(|target| path_ranges(*target, size))
			.collect();
		TreeBuilder {
			wanted,
			..Self::default()
		}
	}

	/// Leaves pushed so far.
	pub fn count(&self) -> u64 {
		self.count
	}

	/// Add the next leaf.
	pub fn push(&mut self, leaf: [u8; 32]) {
		let mut subtree = Subtree {
			start: self.count,
			size: 1,
			hash: leaf,
		};
		self.keep(&subtree);
		self.count += 1;
		while let Some(top) = self.stack.last()
			&& top.size == subtree.size
		{
			let left = self.stack.pop().expect("checked above");
			subtree = Subtree {
				start: left.start,
				size: left.size * 2,
				hash: node_hash(&left.hash, &subtree.hash),
			};
			self.keep(&subtree);
		}
		self.stack.push(subtree);
	}

	fn keep(&mut self, subtree: &Subtree) {
		let range = (subtree.start, subtree.start + subtree.size);
		if self.wanted.contains(&range) {
			self.found.insert(range, subtree.hash);
		}
	}

	/// The root, and the proofs for the targets given to
	/// [`TreeBuilder::for_proofs`] (each bottom-up, as RFC 9162 section
	/// 2.1.3.2 verifies them). A target past the end has no proof.
	pub fn finish(mut self, targets: &[u64]) -> ([u8; 32], BTreeMap<u64, Vec<[u8; 32]>>) {
		let Some(mut acc) = self.stack.pop() else {
			return (empty_root(), BTreeMap::new());
		};
		let end = self.count;
		while let Some(left) = self.stack.pop() {
			acc = Subtree {
				start: left.start,
				size: end - left.start,
				hash: node_hash(&left.hash, &acc.hash),
			};
			self.keep(&acc);
		}
		let mut proofs = BTreeMap::new();
		for target in targets.iter().filter(|target| **target < end) {
			let proof = path_ranges(*target, end)
				.into_iter()
				.filter_map(|range| self.found.get(&range).copied())
				.collect();
			proofs.insert(*target, proof);
		}
		(acc.hash, proofs)
	}
}

/// The leaf ranges whose hashes form the proof of `index` in a tree of
/// `size` leaves, bottom-up (RFC 6962 section 2.1.1, unrolled).
fn path_ranges(index: u64, size: u64) -> Vec<(u64, u64)> {
	let mut ranges = Vec::new();
	let (mut low, mut high) = (0, size);
	while high - low > 1 {
		let split = largest_power_of_two_below(high - low);
		if index < low + split {
			ranges.push((low + split, high));
			high = low + split;
		} else {
			ranges.push((low, low + split));
			low += split;
		}
	}
	ranges.reverse();
	ranges
}

/// The largest power of two strictly below `n` (`n > 1`).
fn largest_power_of_two_below(n: u64) -> u64 {
	1 << (63 - (n - 1).leading_zeros())
}

/// Whether `proof` shows that `leaf` is leaf `index` of the tree of `size`
/// leaves whose root is `root` (RFC 9162 section 2.1.3.2).
pub fn verify_inclusion(
	index: u64,
	size: u64,
	leaf: &[u8; 32],
	proof: &[[u8; 32]],
	root: &[u8; 32],
) -> bool {
	if index >= size {
		return false;
	}
	let (mut fn_, mut sn) = (index, size - 1);
	let mut hash = *leaf;
	for sibling in proof {
		if sn == 0 {
			return false;
		}
		if fn_ & 1 == 1 || fn_ == sn {
			hash = node_hash(sibling, &hash);
			while fn_ & 1 == 0 && fn_ != 0 {
				fn_ >>= 1;
				sn >>= 1;
			}
		} else {
			hash = node_hash(&hash, sibling);
		}
		fn_ >>= 1;
		sn >>= 1;
	}
	sn == 0 && hash == *root
}

#[cfg(test)]
#[path = "merkle_tests.rs"]
mod tests;
