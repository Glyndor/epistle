//! Per-client-IP connection counter for SMTP listeners.
//!
//! A single global semaphore bounds the total number of connections one
//! SMTP listener accepts. That semaphore prevents the listener from
//! exhausting the file-descriptor budget, but it does not stop one peer
//! from monopolising it: a thousand connections from the same IP still
//! succeeds because the per-listener counter is fresh on every accept.
//! Without a per-IP cap a single bot would crowd out every legitimate
//! client until the global cap trips, well after the listening port
//! has stopped being useful.
//!
//! The counter is a `HashMap<IpAddr, usize>` behind one mutex, keyed by
//! [`client_key`]: an IPv4 address, or the /64 of an IPv6 one. A peer
//! over the cap is refused; the next accept from the same peer decrements
//! the count when its connection ends. Trusted CIDRs bypass the cap so
//! the office network is not penalised for opening every account's
//! notification poll. The map is bounded by the number of distinct
//! peers currently in flight, which the per-listener semaphore already
//! caps.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Arc, Mutex};

/// The address a client is counted under: its IPv4 address (also when it
/// arrives IPv4-mapped on a dual-stack socket), or the /64 its IPv6 address
/// belongs to. One subscriber is usually handed a whole /64, so counting
/// single IPv6 addresses would let a client rotate through it.
pub fn client_key(ip: IpAddr) -> IpAddr {
	match ip.to_canonical() {
		IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & !u128::from(u64::MAX))),
		v4 => v4,
	}
}

/// Owned slot: when dropped, the per-IP count for `ip` is decremented.
/// Hand the slot to the connection task so the count is released no
/// matter how the task ends (success, error, panic).
pub struct Slot {
	/// The client key counted for this slot; `None` for a trusted peer,
	/// which is never counted.
	ip: Option<IpAddr>,
	state: Arc<State>,
}

/// Internal counter state shared by every accept loop and every slot.
struct State {
	cap: usize,
	counts: Mutex<HashMap<IpAddr, usize>>,
}

impl State {
	fn try_acquire(self: &Arc<Self>, ip: IpAddr, trusted: &[crate::cidr::Cidr]) -> Option<Slot> {
		if trusted.iter().any(|cidr| cidr.contains(ip)) {
			// Trusted peer: bypass the per-IP cap. The cap is still
			// enforced for every other peer on this listener.
			return Some(Slot {
				ip: None,
				state: Arc::clone(self),
			});
		}
		let ip = client_key(ip);
		let mut counts = self.counts.lock().expect("per-IP counter");
		let current = counts.get(&ip).copied().unwrap_or(0);
		if current >= self.cap {
			return None;
		}
		counts.insert(ip, current + 1);
		Some(Slot {
			ip: Some(ip),
			state: Arc::clone(self),
		})
	}
}

impl Drop for Slot {
	fn drop(&mut self) {
		let Some(ip) = self.ip else {
			return;
		};
		let mut counts = self.state.counts.lock().expect("per-IP counter");
		if let Some(count) = counts.get_mut(&ip) {
			*count = count.saturating_sub(1);
			if *count == 0 {
				counts.remove(&ip);
			}
		}
	}
}

/// A shared per-IP connection counter. One instance lives in the
/// listener's accept loop and is queried on every accept.
pub struct PerIpCounter {
	#[allow(dead_code)]
	cap: usize,
	state: Arc<State>,
}

impl PerIpCounter {
	/// A counter that refuses any peer over `cap` concurrent
	/// connections. `cap == 0` is treated as the default the listener
	/// was built with; production code paths always pass a positive
	/// cap.
	pub fn new(cap: usize) -> Self {
		PerIpCounter {
			cap: cap.max(1),
			state: Arc::new(State {
				cap: cap.max(1),
				counts: Mutex::new(HashMap::new()),
			}),
		}
	}

	/// Try to claim one slot for `ip`. Returns `Some(Slot)` on success;
	/// the slot releases the count on drop. Returns `None` when the
	/// peer is over the cap (or already at the cap on a fresh admit);
	/// `trusted` lists CIDRs exempt from the cap.
	pub fn try_acquire(
		self: &Arc<Self>,
		ip: IpAddr,
		trusted: &[crate::cidr::Cidr],
	) -> Option<Slot> {
		self.state.try_acquire(ip, trusted)
	}

	/// How many clients the map tracks right now.
	#[cfg(test)]
	pub fn tracked(&self) -> usize {
		self.state.counts.lock().expect("per-IP counter").len()
	}

	/// The current count for the client `ip` belongs to. Mostly useful for
	/// tests.
	pub fn count(&self, ip: IpAddr) -> usize {
		self.state
			.counts
			.lock()
			.expect("per-IP counter")
			.get(&client_key(ip))
			.copied()
			.unwrap_or(0)
	}
}

#[cfg(test)]
mod tests;
