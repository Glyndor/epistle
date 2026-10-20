//! Per-account connection counter for the post-authentication phase.
//!
//! Once the listener has accepted a TCP connection and the IMAP or POP3
//! path has authenticated the principal, the server knows the local
//! account the connection belongs to. From that moment on, two caps
//! apply: one per (account, client IP) and one per account in aggregate.
//! Both defaults come from `[server] max_connections_per_account`; the
//! defaults are 10 per (account, IP) and 50 per account, which matches
//! Dovecot's `mail_max_userip_connections` (10) and a sensible total.
//!
//! The counter is shared across IMAP and POP3 so a single account cannot
//! keep more than the configured number of authenticated connections
//! across the two protocols combined. JMAP event sources are not wired to
//! it yet and keep their own limit per credential. A connection over the
//! cap is refused with the protocol's "user is busy" code: IMAP `NO
//! [LIMIT]`, POP3 `-ERR [IN-USE]`. The slot is released
//! on every disconnect path (success, error, panic) because the
//! [`PerAccountSlot`] guard drops it.
//!
//! The map is bounded by the number of distinct (account, IP) pairs that
//! hold a connection at the same time. Every listener that admits
//! authenticated connections already caps the number of in-flight
//! connections, so the map can never grow without bound from a leaking
//! client: once every connection has ended, every entry drops to zero
//! and is removed.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

/// Default per-(account, client IP) cap. Matches `mail_max_userip_connections`
/// in Dovecot: enough for a normal client (an open connection plus an IDLE
/// plus a background sync) and small enough that one compromised client
/// cannot open dozens of sockets in a victim's name.
pub const DEFAULT_PER_ACCOUNT_PER_IP: usize = 10;

/// Default per-account total cap. 50 keeps a compromised account from
/// pinning every listener slot for itself while leaving room for a
/// reasonably busy office behind one IP.
pub const DEFAULT_PER_ACCOUNT_TOTAL: usize = 50;

/// Why a per-account slot could not be acquired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerAccountRefusal {
	/// The (account, IP) pair already holds its cap.
	PerAccountPerIp,
	/// The account already holds its total cap.
	PerAccountTotal,
}

/// An owned per-account slot. Dropping it decrements both counts.
pub struct PerAccountSlot {
	account: String,
	ip: Option<IpAddr>,
	state: Arc<State>,
}

impl std::fmt::Debug for PerAccountSlot {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("PerAccountSlot")
			.field("account", &self.account)
			.field("ip", &self.ip)
			.finish()
	}
}

impl Drop for PerAccountSlot {
	fn drop(&mut self) {
		let Some(ip) = self.ip else {
			return;
		};
		let mut counts = self.state.counts.lock().expect("per-account counter");
		if let Some(by_ip) = counts.by_pair.get_mut(&(self.account.clone(), ip)) {
			*by_ip = by_ip.saturating_sub(1);
			if *by_ip == 0 {
				counts.by_pair.remove(&(self.account.clone(), ip));
			}
		}
		if let Some(total) = counts.by_account.get_mut(&self.account) {
			*total = total.saturating_sub(1);
			if *total == 0 {
				counts.by_account.remove(&self.account);
			}
		}
	}
}

struct State {
	per_ip_cap: usize,
	total_cap: usize,
	counts: Mutex<Counts>,
}

struct Counts {
	by_pair: HashMap<(String, IpAddr), usize>,
	by_account: HashMap<String, usize>,
}

impl State {
	fn try_acquire(
		self: &Arc<Self>,
		account: &str,
		ip: IpAddr,
	) -> Result<PerAccountSlot, PerAccountRefusal> {
		let pair_key = (account.to_string(), ip);
		let mut counts = self.counts.lock().expect("per-account counter");
		let current_pair = counts.by_pair.get(&pair_key).copied().unwrap_or(0);
		if current_pair >= self.per_ip_cap {
			return Err(PerAccountRefusal::PerAccountPerIp);
		}
		let current_total = counts.by_account.get(account).copied().unwrap_or(0);
		if current_total >= self.total_cap {
			return Err(PerAccountRefusal::PerAccountTotal);
		}
		counts.by_pair.insert(pair_key, current_pair + 1);
		counts
			.by_account
			.insert(account.to_string(), current_total + 1);
		Ok(PerAccountSlot {
			account: account.to_string(),
			ip: Some(ip),
			state: Arc::clone(self),
		})
	}
}

/// A shared per-account connection counter. One instance lives in the
/// shared state and is queried after authentication on every IMAP and
/// POP3 connection.
pub struct PerAccountCounter {
	state: Arc<State>,
}

impl PerAccountCounter {
	/// A counter with `per_ip_cap` connections per (account, IP) and
	/// `total_cap` per account. Caps of `0` are clamped to `1` so the
	/// counter can still hand out a slot while remaining meaningful in
	/// tests; production code paths always pass a positive cap.
	pub fn new(per_ip_cap: usize, total_cap: usize) -> Self {
		let per_ip_cap = per_ip_cap.max(1);
		let total_cap = total_cap.max(1);
		PerAccountCounter {
			state: Arc::new(State {
				per_ip_cap,
				total_cap,
				counts: Mutex::new(Counts {
					by_pair: HashMap::new(),
					by_account: HashMap::new(),
				}),
			}),
		}
	}

	/// Try to claim one slot for `account` from `ip`. On success the
	/// returned guard releases both counts on drop. On refusal the error
	/// says which cap tripped.
	pub fn try_acquire(
		self: &Arc<Self>,
		account: &str,
		ip: IpAddr,
	) -> Result<PerAccountSlot, PerAccountRefusal> {
		self.state.try_acquire(account, ip)
	}

	/// The current total count for `account`. Mostly useful for tests.
	#[cfg(test)]
	pub fn total(&self, account: &str) -> usize {
		self.state
			.counts
			.lock()
			.expect("per-account counter")
			.by_account
			.get(account)
			.copied()
			.unwrap_or(0)
	}

	/// The current count for `(account, ip)`. Mostly useful for tests.
	#[cfg(test)]
	pub fn pair(&self, account: &str, ip: IpAddr) -> usize {
		self.state
			.counts
			.lock()
			.expect("per-account counter")
			.by_pair
			.get(&(account.to_string(), ip))
			.copied()
			.unwrap_or(0)
	}

	/// The number of distinct (account, IP) pairs the counter is currently
	/// tracking. The counter must drop the entry the moment a pair's count
	/// returns to zero, so a long stream of distinct connections that all
	/// disconnect leaves the map empty.
	#[cfg(test)]
	pub fn tracked_pairs(&self) -> usize {
		self.state
			.counts
			.lock()
			.expect("per-account counter")
			.by_pair
			.len()
	}

	/// The number of distinct accounts the counter is currently tracking.
	#[cfg(test)]
	pub fn tracked_accounts(&self) -> usize {
		self.state
			.counts
			.lock()
			.expect("per-account counter")
			.by_account
			.len()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn ip(s: &str) -> IpAddr {
		s.parse().unwrap()
	}

	#[test]
	fn per_ip_cap_refuses_one_account_over_the_pair_limit() {
		let counter = Arc::new(PerAccountCounter::new(2, 50));
		let a = counter
			.try_acquire("alice", ip("203.0.113.1"))
			.expect("first");
		let b = counter
			.try_acquire("alice", ip("203.0.113.1"))
			.expect("second");
		assert_eq!(
			counter.try_acquire("alice", ip("203.0.113.1")).unwrap_err(),
			PerAccountRefusal::PerAccountPerIp,
			"the third connection from the same IP for the same account is refused"
		);
		drop(a);
		let c = counter
			.try_acquire("alice", ip("203.0.113.1"))
			.expect("third after drop");
		assert_eq!(counter.pair("alice", ip("203.0.113.1")), 2);
		drop(b);
		drop(c);
		assert_eq!(counter.total("alice"), 0);
		assert_eq!(counter.pair("alice", ip("203.0.113.1")), 0);
	}

	#[test]
	fn the_total_cap_refuses_one_account_across_distinct_ip_addresses() {
		let counter = Arc::new(PerAccountCounter::new(50, 2));
		let a = counter
			.try_acquire("alice", ip("203.0.113.1"))
			.expect("first");
		let b = counter
			.try_acquire("alice", ip("203.0.113.2"))
			.expect("second");
		assert_eq!(
			counter.try_acquire("alice", ip("203.0.113.3")).unwrap_err(),
			PerAccountRefusal::PerAccountTotal,
			"the third IP is refused by the per-account total"
		);
		drop(a);
		let _c = counter
			.try_acquire("alice", ip("203.0.113.3"))
			.expect("third after drop");
		drop(b);
		assert_eq!(counter.total("alice"), 1);
	}

	#[test]
	fn two_accounts_have_independent_counts() {
		let counter = Arc::new(PerAccountCounter::new(2, 2));
		let _a = counter
			.try_acquire("alice", ip("203.0.113.1"))
			.expect("alice");
		let _b = counter
			.try_acquire("alice", ip("203.0.113.2"))
			.expect("alice second");
		let _c = counter
			.try_acquire("bob", ip("203.0.113.1"))
			.expect("bob first");
		let _d = counter
			.try_acquire("bob", ip("203.0.113.2"))
			.expect("bob second");
		assert_eq!(
			counter.try_acquire("alice", ip("203.0.113.3")).unwrap_err(),
			PerAccountRefusal::PerAccountTotal,
			"alice's total of 2 is full"
		);
		assert_eq!(
			counter.try_acquire("bob", ip("203.0.113.3")).unwrap_err(),
			PerAccountRefusal::PerAccountTotal,
			"bob's total of 2 is full"
		);
	}

	#[test]
	fn churn_through_a_thousand_distinct_pairs_leaves_an_empty_map() {
		// The counter's two maps are bounded by the number of distinct
		// pairs that hold a connection at the same time. A long stream
		// of distinct connections that all disconnect must not leave
		// any stale key behind: `Drop` removes the entry the moment its
		// count returns to zero, otherwise the maps grow without bound
		// under sustained churn.
		let counter = Arc::new(PerAccountCounter::new(10, 10_000));
		for index in 0..1_000_u32 {
			let account = format!("user{index}");
			let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(
				203,
				0,
				113,
				((index >> 8) & 0xff) as u8,
			));
			let slot = counter.try_acquire(&account, ip).expect("acquire");
			assert_eq!(counter.pair(&account, ip), 1);
			drop(slot);
			assert_eq!(counter.pair(&account, ip), 0);
			assert_eq!(counter.total(&account), 0);
		}
		assert_eq!(
			counter.tracked_pairs(),
			0,
			"no (account, IP) pair may outlive its slot"
		);
		assert_eq!(
			counter.tracked_accounts(),
			0,
			"no account may outlive its slot"
		);
	}
}
