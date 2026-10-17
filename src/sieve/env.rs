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
pub(super) const MAX_VAR_BYTES: usize = 4096;
/// The most octets all of a run's variables may hold together. A `set` that
/// would pass it is ignored.
pub(super) const MAX_VARS_TOTAL_BYTES: usize = 64 * 1024;
/// The most variables a run may hold, numbered captures included.
pub(super) const MAX_VARS: usize = 128;
/// The longest a variable's name may be.
pub(super) const MAX_VAR_NAME: usize = 64;
/// The most commands executed and tests evaluated in one run.
pub(super) const MAX_STEPS: u32 = 20_000;
/// The most matching work (pattern by text cells, characters copied or built)
/// one run may ask for.
pub(super) const MAX_WORK: u64 = 50_000_000;

/// Variables and counters of one run.
#[derive(Default)]
pub(crate) struct Env {
	vars: HashMap<String, String>,
	var_bytes: usize,
	steps: u32,
	work: u64,
	exhausted: bool,
}

impl Env {
	/// Whether the run spent more than it may: its result is not to be used.
	pub(super) fn exhausted(&self) -> bool {
		self.exhausted
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

	/// The value of the variable `name`, if set.
	#[cfg(test)]
	pub(super) fn get(&self, name: &str) -> Option<&str> {
		self.vars.get(name).map(String::as_str)
	}

	/// Set a variable. The value is cut to [`MAX_VAR_BYTES`] at a character
	/// boundary; a `set` that would pass the total, the number of variables
	/// or the name length is ignored.
	pub(super) fn set(&mut self, name: &str, value: &str) {
		let mut end = value.len().min(MAX_VAR_BYTES);
		while !value.is_char_boundary(end) {
			end -= 1;
		}
		let value = &value[..end];
		let old = self.vars.get(name).map_or(0, String::len);
		let is_new = !self.vars.contains_key(name);
		if name.len() > MAX_VAR_NAME
			|| (is_new && self.vars.len() >= MAX_VARS)
			|| self.var_bytes - old + value.len() > MAX_VARS_TOTAL_BYTES
		{
			return;
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
		let out = super::vars::expand(input, &self.vars, limit);
		self.charge(out.len() as u64);
		out
	}
}

#[cfg(test)]
#[path = "env_tests.rs"]
mod tests;
