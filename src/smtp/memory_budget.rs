//! Server-wide byte budget for SMTP DATA / BDAT.
//!
//! The SMTP server buffers every message body in memory until end-of-DATA: a
//! 25 MiB message sits in one `Vec<u8>` for every concurrent transfer, and
//! the post-DATA stamping path makes several more full copies before the
//! bytes reach the spool. With up to a thousand concurrent connections per
//! listener, a few dozen large messages exhaust the mail container's
//! `mem_limit`.
//!
//! The budget is a single, shared `Arc<MemoryBudget>` every session draws
//! from. A session holds what it claimed in a [`Reservation`], which hands
//! the octets back when it is dropped, so every path that drops the body
//! releases them (a reply, `RSET`, `EHLO`, a disconnect, a timeout, a
//! panic). An accepted body stays reserved until its delivery is over. When the budget is
//! exhausted a new transaction is told `452 4.3.1 insufficient system
//! resources; try again later` at DATA, and a BDAT chunk that would push
//! past the cap is refused the same way.
//!
//! The default cap is derived from the memory the `mail` container may use
//! (see [`crate::smtp::memory_fit`]), a fifth of it, so a busy server
//! stays clear of the OOM. A `[server] message_memory_budget` overrides the
//! derived default; setting it to `0` disables the budget (every
//! reservation succeeds, the historical behaviour).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

/// A quarter of 1 GiB, the fixed budget releases before the derived one
/// used. The server no longer falls back to it; tests use it as the budget
/// of a small install.
pub const DEFAULT_BUDGET_BYTES: u64 = 256 * 1024 * 1024;

/// The share of the budget one client may hold by default: a quarter, so a
/// single source cannot hold more than that while others wait.
pub const CLIENT_SHARE_DIVISOR: u64 = 4;

/// A shared byte budget for in-flight SMTP message transfers. Every
/// session holds an `Arc<MemoryBudget>` and reserves from it on DATA and
/// every BDAT chunk. Reservations are released on every path that drops
/// the in-flight body.
///
/// One client may hold at most `client_share` of it, so a single source
/// trickling large bodies slowly cannot hold the whole budget and refuse
/// everybody else. Clients are keyed like the per-IP connection cap: the
/// IPv4 address, or the /64 of an IPv6 one.
pub struct MemoryBudget {
	cap: u64,
	client_share: u64,
	usage: Mutex<Usage>,
}

/// What is held, in total and per client.
#[derive(Default)]
struct Usage {
	used: u64,
	per_client: HashMap<IpAddr, u64>,
}

impl std::fmt::Debug for MemoryBudget {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		formatter
			.debug_struct("MemoryBudget")
			.field("cap", &self.cap)
			.field("client_share", &self.client_share)
			.field("used", &self.used())
			.finish()
	}
}

impl MemoryBudget {
	/// A budget that admits every reservation. The historical behaviour
	/// for `[server] message_memory_budget = 0` and the default for
	/// tests that do not wire the budget in.
	pub fn unlimited() -> Self {
		Self::with_cap(0)
	}

	/// A budget with the given cap in bytes. `0` is the unlimited
	/// variant; any positive value is the upper bound on the sum of
	/// in-flight reservations. One client may take all of it until
	/// [`Self::with_client_share`] says otherwise.
	pub fn with_cap(cap: u64) -> Self {
		MemoryBudget {
			cap,
			client_share: cap,
			usage: Mutex::new(Usage::default()),
		}
	}

	/// Limit what one client may hold at once to `share` bytes (at most
	/// the cap).
	pub fn with_client_share(mut self, share: u64) -> Self {
		self.client_share = share.min(self.cap);
		self
	}

	/// The configured cap, in bytes. `0` means unlimited.
	pub fn cap(&self) -> u64 {
		self.cap
	}

	/// The most one client may hold at once, in bytes.
	pub fn client_share(&self) -> u64 {
		self.client_share
	}

	/// The bytes currently reserved. Includes DATA, BDAT chunks that have
	/// been admitted but not yet finalized, and bodies being delivered.
	pub fn used(&self) -> u64 {
		self.usage.lock().expect("memory budget").used
	}

	/// Try to claim `bytes` octets with no client attached (a session that
	/// does not know its peer). See [`Self::try_reserve_for`].
	pub fn try_reserve(&self, bytes: u64) -> Result<(), u64> {
		self.try_reserve_for(None, bytes)
	}

	/// Try to claim `bytes` octets for `client`. `Ok(())` when the claim
	/// fits the cap and the client's share (or the budget is unlimited),
	/// `Err(bytes)` otherwise, with nothing claimed. Every claim must be
	/// handed back with [`Self::release_for`] and the same client;
	/// [`Reservation`] does that when dropped.
	pub fn try_reserve_for(&self, client: Option<IpAddr>, bytes: u64) -> Result<(), u64> {
		if self.cap == 0 {
			return Ok(());
		}
		let mut usage = self.usage.lock().expect("memory budget");
		if usage.used.saturating_add(bytes) > self.cap {
			return Err(bytes);
		}
		if let Some(client) = client {
			let held = usage.per_client.get(&client).copied().unwrap_or(0);
			if held.saturating_add(bytes) > self.client_share {
				return Err(bytes);
			}
			usage.per_client.insert(client, held + bytes);
		}
		usage.used += bytes;
		Ok(())
	}

	/// Release a claim made with [`Self::try_reserve`].
	pub fn release(&self, bytes: u64) {
		self.release_for(None, bytes);
	}

	/// Release a claim made with [`Self::try_reserve_for`]. Saturating: a
	/// release larger than what is held clamps to zero rather than wrap.
	pub fn release_for(&self, client: Option<IpAddr>, bytes: u64) {
		if self.cap == 0 || bytes == 0 {
			return;
		}
		let mut usage = self.usage.lock().expect("memory budget");
		usage.used = usage.used.saturating_sub(bytes);
		if let Some(client) = client
			&& let Some(held) = usage.per_client.get_mut(&client)
		{
			*held = held.saturating_sub(bytes);
			if *held == 0 {
				usage.per_client.remove(&client);
			}
		}
	}
}

/// Octets held against a [`MemoryBudget`] for one body or one chunk.
///
/// The octets go back to the budget when the value is dropped, so every
/// path that discards the body (a reply, `RSET`, `EHLO`, a disconnect, a
/// timeout, a panic that unwinds the session task) releases them without
/// having to remember to.
#[derive(Default)]
pub struct Reservation {
	budget: Option<Arc<MemoryBudget>>,
	client: Option<IpAddr>,
	bytes: u64,
}

impl Reservation {
	/// A reservation that holds nothing.
	pub fn none() -> Self {
		Reservation::default()
	}

	/// Claim `bytes` more octets from `budget` for the client `peer`
	/// belongs to. On refusal nothing is claimed and the octets the
	/// reservation already holds stay held.
	pub fn try_grow(
		&mut self,
		budget: &Arc<MemoryBudget>,
		peer: Option<IpAddr>,
		bytes: u64,
	) -> Result<(), u64> {
		let client = peer.map(crate::smtp::per_ip::client_key);
		budget.try_reserve_for(client, bytes)?;
		if self.budget.is_none() {
			self.budget = Some(Arc::clone(budget));
			self.client = client;
		}
		self.bytes = self.bytes.saturating_add(bytes);
		Ok(())
	}

	/// Take over the octets `other` holds; they are released with `self`.
	pub fn absorb(&mut self, mut other: Reservation) {
		if self.budget.is_none() {
			self.budget = other.budget.take();
			self.client = other.client;
		}
		self.bytes = self.bytes.saturating_add(std::mem::take(&mut other.bytes));
	}

	/// The octets held.
	pub fn bytes(&self) -> u64 {
		self.bytes
	}
}

impl Drop for Reservation {
	fn drop(&mut self) {
		if let Some(budget) = &self.budget {
			budget.release_for(self.client, self.bytes);
		}
	}
}

impl std::fmt::Debug for Reservation {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		formatter
			.debug_struct("Reservation")
			.field("bytes", &self.bytes)
			.finish()
	}
}

/// Two reservations are equal when they hold the same number of octets,
/// which is all a comparison of session states needs.
impl PartialEq for Reservation {
	fn eq(&self, other: &Self) -> bool {
		self.bytes == other.bytes
	}
}

impl Eq for Reservation {}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn unlimited_admits_every_reservation() {
		let budget = MemoryBudget::unlimited();
		assert!(budget.try_reserve(1).is_ok());
		assert!(budget.try_reserve(usize::MAX as u64).is_ok());
	}

	#[test]
	fn reservation_fails_when_over_cap() {
		let budget = MemoryBudget::with_cap(100);
		assert!(budget.try_reserve(60).is_ok());
		assert_eq!(budget.try_reserve(50), Err(50));
		assert_eq!(budget.used(), 60);
	}

	#[test]
	fn release_frees_the_bytes_for_the_next_reservation() {
		let budget = MemoryBudget::with_cap(100);
		assert!(budget.try_reserve(60).is_ok());
		budget.release(60);
		assert!(budget.try_reserve(80).is_ok());
	}

	#[test]
	fn a_reservation_hands_its_octets_back_when_dropped() {
		let budget = Arc::new(MemoryBudget::with_cap(100));
		let mut held = Reservation::none();
		assert!(held.try_grow(&budget, None, 30).is_ok());
		let mut chunk = Reservation::none();
		assert!(chunk.try_grow(&budget, None, 50).is_ok());
		held.absorb(chunk);
		assert_eq!((held.bytes(), budget.used()), (80, 80));
		assert_eq!(held.try_grow(&budget, None, 30), Err(30));
		assert_eq!(
			held.bytes(),
			80,
			"a refused claim leaves the held octets alone"
		);
		drop(held);
		assert_eq!(budget.used(), 0);
	}

	#[test]
	fn release_saturates_on_over_release() {
		let budget = MemoryBudget::with_cap(100);
		assert!(budget.try_reserve(40).is_ok());
		budget.release(200);
		assert_eq!(budget.used(), 0);
	}
}
