//! The state of one run of a script, and the budget the run has to stay in.
//!
//! A script is text its owner wrote, run against mail anyone can send, so
//! what it can make the server do in one run is bounded here and not left to
//! the script: how many variables it may keep and how long they may be, how
//! long a string it can build with `${...}`, how many commands and tests it
//! may execute, and how much matching work it may ask for. A run that
//! overspends is abandoned (see [`Env::exhausted`]) and the message is kept.

use std::collections::HashMap;

/// The longest a variable's value may be, in octets (RFC 5229 section 4.1
/// lets a server keep as little as 4000). A longer value is cut.
pub(crate) const MAX_VAR_BYTES: usize = 4096;
/// The most octets all of a run's variables may hold together. A `set` that
/// would pass it is ignored.
pub(crate) const MAX_VARS_TOTAL_BYTES: usize = 64 * 1024;
/// The most variables a run may hold, numbered captures included.
pub(crate) const MAX_VARS: usize = 128;
/// The longest a variable's name may be.
pub(crate) const MAX_VAR_NAME: usize = 64;
/// The most commands executed and tests evaluated in one run.
pub(crate) const MAX_STEPS: u32 = 20_000;
/// The work (octets compared, characters copied or built) one run may ask
/// for: 256 MiB worth, a hard ceiling that does not move with the message.
/// What a test reads of the body or of a header is a fixed window
/// ([`BODY_WINDOW`], [`HEADER_NAME_VALUES`], [`HEADER_NAME_WINDOW`]), so
/// the sender's choice of a bigger message does not make a test cost more,
/// and a script runs out of work for a big message exactly when it would for a
/// small one: when it asks for more than this many octets of reading.
pub(crate) const MAX_WORK: u64 = 256 * 1024 * 1024;
/// How much of the body the `body` test reads: the first mebibyte.
pub(super) const BODY_WINDOW: usize = 1024 * 1024;
/// What a lookup reads of the headers called one name: the first 1000 values,
/// and the first 64 KiB of them in all (a value is cut at that too). Every
/// name a test lists has a quota of its own, so that a name with a thousand
/// values or one huge value cannot use up what another is allowed to show.
pub(super) const HEADER_NAME_VALUES: usize = 1000;
/// See [`HEADER_NAME_VALUES`]: the octets a lookup reads of one name.
pub(super) const HEADER_NAME_WINDOW: usize = 64 * 1024;
/// How many names one lookup reads (the rest of a longer list are not looked
/// at). With the quotas above, a lookup reads at most 1 MiB, as much as a
/// `body` test does.
pub(super) const HEADER_NAMES_PER_LOOKUP: usize = 16;

/// How many headers of a message the interpreter reads: the first 10 000.
/// A message may hold millions of one-letter headers, and copying and
/// indexing each one cost the server hundreds of mebibytes per recipient with
/// a filter. What comes after is not visible to a test. The sender gains
/// nothing by it, since a header it hides it could have left out, and what the
/// server itself adds comes first.
pub(crate) const MAX_HEADERS: usize = 10_000;

/// Variables and counters of one run.
#[derive(Default)]
pub(crate) struct Env {
	vars: HashMap<String, String>,
	/// `${0}` to `${32}`: what the last successful `:matches` captured. They
	/// are the sender's text, and have a store of their own, so that what a
	/// sender makes them hold cannot use up the script's variables.
	captures: Vec<String>,
	var_bytes: usize,
	steps: u32,
	work: u64,
	exhausted: bool,
	/// A test did not look at the whole of what it was asked about: a body
	/// past its window, more headers than a lookup visits.
	truncated: bool,
	/// A `:matches` key was over the length or wildcard caps.
	pattern_over_caps: bool,
}

impl Env {
	/// Whether the run spent more than it may: it stops where it is.
	pub(super) fn exhausted(&self) -> bool {
		self.exhausted
	}

	/// Note that a test looked at less than the whole message.
	pub(super) fn mark_truncated(&mut self) {
		self.truncated = true;
	}

	/// Note that a `:matches` key is over the caps and was taken as false.
	pub(super) fn note_pattern_over_caps(&mut self) {
		self.pattern_over_caps = true;
	}

	/// Whether a `:matches` key was over the caps in this run.
	pub(super) fn pattern_over_caps(&self) -> bool {
		self.pattern_over_caps
	}

	/// Whether any test looked at less than the whole message.
	pub(super) fn truncated(&self) -> bool {
		self.truncated
	}

	/// Count one command or test; `false` once the run is out of steps.
	pub(super) fn step(&mut self) -> bool {
		self.steps = self.steps.saturating_add(1);
		if self.steps > MAX_STEPS {
			self.exhausted = true;
		}
		!self.exhausted
	}

	/// Give the run up: something it asked for cannot be answered, and a wrong
	/// answer ("no match") would let a message past a filter.
	pub(super) fn abandon(&mut self) {
		self.exhausted = true;
	}

	/// The work the run may still spend.
	pub(super) fn remaining_work(&self) -> u64 {
		MAX_WORK.saturating_sub(self.work)
	}

	/// Spend `units` of work; `false` once the run is out of it.
	pub(super) fn charge(&mut self, units: u64) -> bool {
		self.work = self.work.saturating_add(units);
		if self.work > MAX_WORK {
			self.exhausted = true;
		}
		!self.exhausted
	}

	/// The value of the variable `name`, if set. A name made of digits is a
	/// match variable.
	pub(super) fn get(&self, name: &str) -> Option<&str> {
		match capture_index(name) {
			Some(index) => self.captures.get(index).map(String::as_str),
			None => self.vars.get(name).map(String::as_str),
		}
	}

	/// Replace the match variables with those of a `:matches` that succeeded:
	/// `${0}` is the whole value and `${1}` on the wildcards. Each is cut to
	/// [`MAX_VAR_BYTES`], and there are at most 33.
	pub(super) fn set_captures(&mut self, whole: &str, parts: Vec<String>) {
		self.captures.clear();
		self.captures.push(cut(whole, MAX_VAR_BYTES).to_string());
		for part in parts.into_iter().take(super::compare::MAX_WILDCARDS) {
			self.captures.push(cut(&part, MAX_VAR_BYTES).to_string());
		}
	}

	/// Set a variable. The value is cut to [`MAX_VAR_BYTES`] at a character
	/// boundary. A `set` that does not fit (the total, the number of variables,
	/// the length of the name) is not carried out and stops the run: silence
	/// would let what a message makes the store hold decide whether the rest of
	/// the script does what it says.
	pub(super) fn set(&mut self, name: &str, value: &str) {
		let value = cut(value, MAX_VAR_BYTES);
		if let Some(index) = capture_index(name) {
			if index > super::compare::MAX_WILDCARDS {
				return self.abandon();
			}
			if self.captures.len() <= index {
				self.captures.resize(index + 1, String::new());
			}
			self.captures[index] = value.to_string();
			return;
		}
		let old = self.vars.get(name).map_or(0, String::len);
		let is_new = !self.vars.contains_key(name);
		if name.len() > MAX_VAR_NAME
			|| (is_new && self.vars.len() >= MAX_VARS)
			|| self.var_bytes - old + value.len() > MAX_VARS_TOTAL_BYTES
		{
			return self.abandon();
		}
		self.var_bytes = self.var_bytes - old + value.len();
		self.vars.insert(name.to_string(), value.to_string());
	}

	/// The octets all variables hold.
	#[cfg(test)]
	pub(super) fn var_bytes(&self) -> usize {
		self.var_bytes
	}

	/// `input` with its `${name}` references replaced (see
	/// [`super::vars::expand`]). The result is built no longer than the larger
	/// of the input and [`MAX_VAR_BYTES`]: what a script writes literally is
	/// never cut, what its variables add is bounded, and nothing past the limit
	/// is ever allocated. The octets read and written are charged to the run.
	pub(super) fn expand(&mut self, input: &str) -> String {
		self.charge(input.len() as u64);
		let limit = input.len().max(MAX_VAR_BYTES);
		let out = super::vars::expand(input, |name| self.get(name), limit);
		self.charge(out.len() as u64);
		out
	}
}

/// The match variable a name stands for: `0` to a few digits.
fn capture_index(name: &str) -> Option<usize> {
	(!name.is_empty() && name.len() <= 3 && name.bytes().all(|b| b.is_ascii_digit()))
		.then(|| name.parse().ok())
		.flatten()
}

/// `text` cut to `limit` octets at a character boundary.
fn cut(text: &str, limit: usize) -> &str {
	let mut end = text.len().min(limit);
	while !text.is_char_boundary(end) {
		end -= 1;
	}
	&text[..end]
}

#[cfg(test)]
#[path = "env_tests.rs"]
mod tests;
