//! A list of `:contains` keys tried against one text in one pass.
//!
//! A test with a long list of keys (a block-list of words) used to make one
//! pass over the text per key. Over a body of a mebibyte, a thousand words
//! cost a thousand mebibytes of reading, more than a run may spend, and the
//! sender needed only a big message to make the run give up before the rules
//! that follow. The keys are built into an Aho-Corasick automaton instead, so
//! the cost is the text once plus the keys once, whatever their number.

use std::collections::VecDeque;

use super::compare::MatchSpec;
use super::env::Env;

/// Below this many keys, one pass per key is cheaper than building the set.
const MIN_KEYS: usize = 8;

/// Above this many octets of keys the set is not built (a state per octet
/// would be megabytes per test and per message); one pass per key is made, and
/// charged as such.
const MAX_KEY_BYTES: usize = 64 * 1024;

/// What a pass costs a run at least, whatever the lengths: the same minimum a
/// single comparison pays.
const KEY_COST: u64 = 64;

struct Node {
	/// The next state for each byte, sorted by byte.
	next: Vec<(u8, u32)>,
	fail: u32,
	/// A key ends here, or at a state this one falls back to.
	end: bool,
}

/// The byte as the keys are compared: lower case when case is ignored.
fn fold_byte(fold: bool, byte: u8) -> u8 {
	if fold {
		byte.to_ascii_lowercase()
	} else {
		byte
	}
}

/// An automaton that finds whether any of a set of keys is in a text.
struct Automaton {
	nodes: Vec<Node>,
	fold: bool,
}

impl Automaton {
	fn go(&self, state: u32, byte: u8) -> Option<u32> {
		let next = &self.nodes[state as usize].next;
		next.binary_search_by_key(&byte, |&(b, _)| b)
			.ok()
			.map(|at| next[at].1)
	}

	fn build(keys: &[String], fold: bool) -> Automaton {
		let mut automaton = Automaton {
			nodes: vec![Node {
				next: Vec::new(),
				fail: 0,
				end: false,
			}],
			fold,
		};
		for key in keys {
			let mut state = 0u32;
			for byte in key.bytes().map(|b| fold_byte(fold, b)) {
				let next = &automaton.nodes[state as usize].next;
				state = match next.binary_search_by_key(&byte, |&(b, _)| b) {
					Ok(at) => next[at].1,
					Err(at) => {
						let made = automaton.nodes.len() as u32;
						automaton.nodes.push(Node {
							next: Vec::new(),
							fail: 0,
							end: false,
						});
						automaton.nodes[state as usize]
							.next
							.insert(at, (byte, made));
						made
					}
				};
			}
			automaton.nodes[state as usize].end = true;
		}
		automaton.link();
		automaton
	}

	/// Set each state's fallback: the longest proper suffix of what it stands
	/// for that is the start of some key. Breadth first, so a fallback is
	/// always set before the states that use it.
	fn link(&mut self) {
		let mut queue: VecDeque<u32> = self.nodes[0].next.iter().map(|&(_, n)| n).collect();
		while let Some(state) = queue.pop_front() {
			for at in 0..self.nodes[state as usize].next.len() {
				let (byte, child) = self.nodes[state as usize].next[at];
				let mut back = self.nodes[state as usize].fail;
				let fallback = loop {
					if let Some(found) = self.go(back, byte) {
						break found;
					}
					if back == 0 {
						break 0;
					}
					back = self.nodes[back as usize].fail;
				};
				self.nodes[child as usize].fail = fallback;
				self.nodes[child as usize].end |= self.nodes[fallback as usize].end;
				queue.push_back(child);
			}
		}
	}

	fn found_in(&self, text: &str) -> bool {
		let mut state = 0u32;
		for byte in text.bytes().map(|b| fold_byte(self.fold, b)) {
			loop {
				if let Some(next) = self.go(state, byte) {
					state = next;
					break;
				}
				if state == 0 {
					break;
				}
				state = self.nodes[state as usize].fail;
			}
			if self.nodes[state as usize].end {
				return true;
			}
		}
		false
	}
}

/// The keys of one test, with the automaton that finds them all at once when
/// the test is a `:contains` of enough keys.
pub(super) struct Keys<'k> {
	keys: &'k [String],
	set: Option<Automaton>,
	/// A key is empty: every text contains it.
	empty_key: bool,
}

impl<'k> Keys<'k> {
	/// Prepare `keys` for `spec`. The set is built only for `:contains` with
	/// enough keys, and what it takes to build it (the octets of the keys) is
	/// charged to the run before anything is allocated.
	pub(super) fn new(spec: &MatchSpec, keys: &'k [String], env: &mut Env) -> Keys<'k> {
		let mut prepared = Keys {
			keys,
			set: None,
			empty_key: false,
		};
		let Some(fold) = spec.contains_fold() else {
			return prepared;
		};
		let bytes: usize = keys.iter().map(String::len).sum();
		if keys.len() < MIN_KEYS || bytes > MAX_KEY_BYTES {
			return prepared;
		}
		if !env.charge(bytes as u64 + KEY_COST * keys.len() as u64) {
			return prepared;
		}
		prepared.empty_key = keys.iter().any(String::is_empty);
		prepared.set = Some(Automaton::build(keys, fold));
		prepared
	}

	/// Whether `value`, which the caller has paid for reading, matches any
	/// key.
	pub(super) fn any(&self, spec: &MatchSpec, value: &str, env: &mut Env) -> bool {
		let Some(set) = &self.set else {
			return self.keys.iter().any(|key| spec.test_read(value, key, env));
		};
		// One pass over the text, whatever the number of keys.
		if !env.charge(value.len() as u64 + KEY_COST) {
			return false;
		}
		self.empty_key || set.found_in(value)
	}
}

#[cfg(test)]
#[path = "key_set_tests.rs"]
mod tests;
