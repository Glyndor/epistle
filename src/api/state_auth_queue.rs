//! Who holds the places in the queue for the argon2 gate.
//!
//! The queue is bounded as a whole, and a single origin may hold only a few of
//! its places: two per client (an IPv4 address or an IPv6 /64) and four per
//! IPv6 /48. Without that, one address sending guesses in a burst fills the
//! 64 places and the operator is told to come back.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

/// Places one client may hold.
pub(super) const PER_CLIENT: usize = 2;
/// Places one IPv6 /48 may hold.
pub(super) const PER_NET: usize = 4;

/// An IPv4 address, an IPv6 /64, or no address at all.
type Client = Option<(bool, u64)>;

fn client_of(ip: Option<IpAddr>) -> Client {
	ip.map(|ip| match ip {
		IpAddr::V4(v4) => (false, u64::from(u32::from(v4))),
		IpAddr::V6(v6) => (true, (u128::from(v6) >> 64) as u64),
	})
}

/// The /48 of an IPv6 client; none for the rest.
fn net_of(client: Client) -> Option<u64> {
	client.and_then(|(v6, bits)| v6.then_some(bits >> 16))
}

/// The places taken now, in total and by whom.
#[derive(Default)]
pub(super) struct QueueSlots {
	total: usize,
	clients: HashMap<Client, usize>,
	nets: HashMap<u64, usize>,
}

impl QueueSlots {
	/// Test-only: clients and /48s with a place held.
	#[cfg(test)]
	pub(super) fn tracked(&self) -> (usize, usize) {
		(self.clients.len(), self.nets.len())
	}

	#[cfg(test)]
	pub(super) fn total(&self) -> usize {
		self.total
	}
}

/// A place in the queue, given back on drop (so also when the request is
/// cancelled while it waits).
pub(super) struct Waiting<'a> {
	slots: &'a Mutex<QueueSlots>,
	client: Client,
}

impl<'a> Waiting<'a> {
	/// Take a place for `ip` if the queue, the client and its /48 have room.
	pub(super) fn enter(
		slots: &'a Mutex<QueueSlots>,
		ip: Option<IpAddr>,
		max_total: usize,
	) -> Option<Self> {
		let client = client_of(ip);
		let net = net_of(client);
		let mut held = slots.lock().unwrap_or_else(|p| p.into_inner());
		if held.total >= max_total
			|| held.clients.get(&client).copied().unwrap_or(0) >= PER_CLIENT
			|| net.is_some_and(|n| held.nets.get(&n).copied().unwrap_or(0) >= PER_NET)
		{
			return None;
		}
		held.total += 1;
		*held.clients.entry(client).or_default() += 1;
		if let Some(n) = net {
			*held.nets.entry(n).or_default() += 1;
		}
		Some(Self { slots, client })
	}
}

impl Drop for Waiting<'_> {
	fn drop(&mut self) {
		let mut held = self.slots.lock().unwrap_or_else(|p| p.into_inner());
		held.total = held.total.saturating_sub(1);
		if let Some(count) = held.clients.get_mut(&self.client) {
			*count -= 1;
			if *count == 0 {
				held.clients.remove(&self.client);
			}
		}
		if let Some(n) = net_of(self.client)
			&& let Some(count) = held.nets.get_mut(&n)
		{
			*count -= 1;
			if *count == 0 {
				held.nets.remove(&n);
			}
		}
	}
}
