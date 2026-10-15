//! How many submissions may be inspected at once, in total and per
//! account. An inspection is CPU work bounded per message (linear, with a
//! deadline), but nothing else stopped one account from sending crafted
//! heavy messages on many connections and keeping every core busy while
//! other accounts waited. Past either cap the submission is answered with
//! a temporary failure at once, so the client retries and nothing waits
//! behind it.

use std::collections::HashMap;
use std::sync::Mutex;

/// Concurrent inspections for the whole server, at least two.
pub(super) fn default_global_cap() -> usize {
	std::thread::available_parallelism()
		.map(usize::from)
		.unwrap_or(2)
		.max(2)
}

/// Concurrent inspections for one account: a quarter of the global cap,
/// at least one, so one account can never hold every slot.
pub(super) fn default_account_cap(global: usize) -> usize {
	(global / 4).max(1)
}

/// The counters behind the caps.
pub(super) struct Gate {
	global_cap: usize,
	account_cap: usize,
	/// In-flight inspections per account. An account leaves the map when
	/// its count drops to zero, so the map never holds more entries than
	/// the global cap.
	in_flight: Mutex<HashMap<String, usize>>,
}

/// One admitted inspection; dropping it frees the slot.
pub(super) struct Permit<'a> {
	gate: &'a Gate,
	account: String,
}

impl Gate {
	/// A gate with these caps (each at least one).
	pub(super) fn new(global_cap: usize, account_cap: usize) -> Self {
		Self {
			global_cap: global_cap.max(1),
			account_cap: account_cap.max(1),
			in_flight: Mutex::new(HashMap::new()),
		}
	}

	/// Admit one inspection for `account`, or `None` when the server or
	/// the account is at its cap. A poisoned lock admits nothing.
	pub(super) fn try_enter(&self, account: &str) -> Option<Permit<'_>> {
		let mut in_flight = self.in_flight.lock().ok()?;
		let total: usize = in_flight.values().sum();
		let mine = in_flight.get(account).copied().unwrap_or(0);
		if total >= self.global_cap || mine >= self.account_cap {
			return None;
		}
		in_flight.insert(account.to_string(), mine + 1);
		Some(Permit {
			gate: self,
			account: account.to_string(),
		})
	}

	#[cfg(test)]
	pub(super) fn accounts(&self) -> usize {
		self.in_flight.lock().map(|map| map.len()).unwrap_or(0)
	}
}

impl Drop for Permit<'_> {
	fn drop(&mut self) {
		let Ok(mut in_flight) = self.gate.in_flight.lock() else {
			return;
		};
		if let Some(count) = in_flight.get_mut(&self.account) {
			*count -= 1;
			if *count == 0 {
				in_flight.remove(&self.account);
			}
		}
	}
}
