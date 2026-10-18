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
mod tests {
	use super::*;

	#[test]
	fn cap_refuses_extra_connections_from_same_ip() {
		let counter = Arc::new(PerIpCounter::new(2));
		let peer: IpAddr = "203.0.113.1".parse().unwrap();
		let a = counter.try_acquire(peer, &[]).expect("first");
		let b = counter.try_acquire(peer, &[]).expect("second");
		assert!(counter.try_acquire(peer, &[]).is_none(), "third refused");
		drop(a);
		assert!(
			counter.try_acquire(peer, &[]).is_some(),
			"slot freed by drop"
		);
		drop(b);
		assert_eq!(counter.count(peer), 0);
	}

	#[test]
	fn different_ips_track_independently() {
		let counter = Arc::new(PerIpCounter::new(1));
		let a: IpAddr = "203.0.113.1".parse().unwrap();
		let b: IpAddr = "203.0.113.2".parse().unwrap();
		let slot_a = counter.try_acquire(a, &[]).expect("a first");
		assert!(
			counter.try_acquire(b, &[]).is_some(),
			"b has its own counter, independent of a"
		);
		assert!(
			counter.try_acquire(a, &[]).is_none(),
			"a is over the cap of 1"
		);
		drop(slot_a);
		assert!(counter.try_acquire(a, &[]).is_some());
	}

	#[test]
	fn ipv6_addresses_in_one_slash_64_share_the_cap() {
		// One subscriber is handed a whole /64; rotating through it must
		// not buy another connection.
		let counter = Arc::new(PerIpCounter::new(2));
		let first: IpAddr = "2001:db8:1:2::1".parse().unwrap();
		let second: IpAddr = "2001:db8:1:2::2".parse().unwrap();
		let third: IpAddr = "2001:db8:1:2:ffff:ffff:ffff:ffff".parse().unwrap();
		let other: IpAddr = "2001:db8:1:3::1".parse().unwrap();
		let _a = counter.try_acquire(first, &[]).expect("first");
		let _b = counter.try_acquire(second, &[]).expect("second");
		assert!(
			counter.try_acquire(third, &[]).is_none(),
			"a third address in the same /64 is over the cap"
		);
		assert!(
			counter.try_acquire(other, &[]).is_some(),
			"the next /64 is another client"
		);
	}

	#[test]
	fn an_ipv4_mapped_peer_counts_as_its_ipv4_address() {
		let counter = Arc::new(PerIpCounter::new(1));
		let plain: IpAddr = "203.0.113.1".parse().unwrap();
		let mapped: IpAddr = "::ffff:203.0.113.1".parse().unwrap();
		let _slot = counter.try_acquire(plain, &[]).expect("plain");
		assert!(
			counter.try_acquire(mapped, &[]).is_none(),
			"the mapped form is the same client"
		);
	}

	#[test]
	fn the_map_forgets_a_client_whose_connections_have_all_ended() {
		// The key is chosen by whoever connects, so a leftover entry per
		// address would let a client grow the map without bound.
		let counter = Arc::new(PerIpCounter::new(2));
		for n in 0..1000u32 {
			let v4: IpAddr = std::net::Ipv4Addr::from(0x0a00_0000 + n).into();
			let v6: IpAddr = std::net::Ipv6Addr::from((u128::from(n) + 1) << 64).into();
			let first = counter.try_acquire(v4, &[]).expect("v4");
			let second = counter.try_acquire(v6, &[]).expect("v6");
			assert_eq!(counter.tracked(), 2);
			drop((first, second));
			assert_eq!(counter.tracked(), 0, "entry {n} was left behind");
		}
	}

	#[test]
	fn trusted_cidrs_bypass_the_cap() {
		let counter = Arc::new(PerIpCounter::new(1));
		let peer: IpAddr = "10.0.0.5".parse().unwrap();
		let trusted = vec![crate::cidr::Cidr::parse("10.0.0.0/8").unwrap()];
		assert!(counter.try_acquire(peer, &trusted).is_some());
		// Second slot is admitted even though the cap is 1.
		assert!(counter.try_acquire(peer, &trusted).is_some());
	}
}
