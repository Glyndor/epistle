//! How many attachment inspections may run at once, in total and per
//! sender. An inspection is CPU work bounded per message (linear, with a
//! deadline), but nothing else stopped one sender from sending crafted
//! heavy messages on many connections and keeping every core, or every
//! blocking thread, busy while other senders waited. Past either cap the
//! message is answered with a temporary failure at once, so the client
//! retries and nothing waits behind it.
//!
//! A sender is an account for submissions and a client address (the IPv4
//! address, or the /64 of an IPv6 one) for inbound mail.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Concurrent inspections for the whole server, at least two.
pub(crate) fn default_global_cap() -> usize {
	std::thread::available_parallelism()
		.map(usize::from)
		.unwrap_or(2)
		.max(2)
}

/// Concurrent inspections for one sender: a quarter of the global cap, at
/// least one, so one sender can never hold every slot.
pub(crate) fn default_share(global: usize) -> usize {
	(global / 4).max(1)
}

/// The counters behind the caps.
#[derive(Debug)]
pub(crate) struct Gate {
	global_cap: usize,
	share_cap: usize,
	/// In-flight inspections per sender. A sender leaves the map when its
	/// count drops to zero, so the map never holds more entries than the
	/// global cap.
	in_flight: Mutex<HashMap<String, usize>>,
}

/// One admitted inspection; dropping it frees the slot. It owns its gate,
/// so it can travel with the work to another thread and the slot stays
/// taken for as long as the work runs.
#[derive(Debug)]
pub(crate) struct Permit {
	gate: Arc<Gate>,
	sender: String,
}

impl Gate {
	/// A gate with these caps (each at least one).
	pub(crate) fn new(global_cap: usize, share_cap: usize) -> Arc<Self> {
		Arc::new(Self {
			global_cap: global_cap.max(1),
			share_cap: share_cap.max(1),
			in_flight: Mutex::new(HashMap::new()),
		})
	}

	/// A gate with the default caps.
	pub(crate) fn with_defaults() -> Arc<Self> {
		let global = default_global_cap();
		Self::new(global, default_share(global))
	}

	/// Admit one inspection for `sender`, or `None` when the server or the
	/// sender is at its cap. A poisoned lock admits nothing.
	pub(crate) fn try_enter(self: &Arc<Self>, sender: &str) -> Option<Permit> {
		let mut in_flight = self.in_flight.lock().ok()?;
		let total: usize = in_flight.values().sum();
		let mine = in_flight.get(sender).copied().unwrap_or(0);
		if total >= self.global_cap || mine >= self.share_cap {
			return None;
		}
		in_flight.insert(sender.to_string(), mine + 1);
		Some(Permit {
			gate: Arc::clone(self),
			sender: sender.to_string(),
		})
	}

	/// Senders with an inspection in flight.
	#[cfg(test)]
	pub(crate) fn senders(&self) -> usize {
		self.in_flight.lock().map(|map| map.len()).unwrap_or(0)
	}
}

impl Drop for Permit {
	fn drop(&mut self) {
		let Ok(mut in_flight) = self.gate.in_flight.lock() else {
			return;
		};
		if let Some(count) = in_flight.get_mut(&self.sender) {
			*count -= 1;
			if *count == 0 {
				in_flight.remove(&self.sender);
			}
		}
	}
}
