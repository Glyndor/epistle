//! Shared authentication ban store.
//!
//! Every listener (SMTP submission, IMAP, POP3, ManageSieve, the API, OAuth
//! grants) records its authentication failures here, and every listener
//! asks this store whether the subject (a client IP or an account name) is
//! banned before doing any password hashing. The product context's defaults
//! drive the policy: 5 failed authentications in 15 minutes trigger a ban;
//! the first ban lasts 15 minutes, the next on the same subject 30 minutes,
//! then an hour, ... capped at 24 hours. A successful authentication
//! clears the ban and the failure history of the account and of the
//! (account, client) pair it came from, never of the client address: an
//! attacker who owns one account must not be able to reset its own counter
//! by logging in between guesses at others.
//!
//! Failures are counted on three subjects. The client (`ip:`) is the
//! address, or the /64 for IPv6, since one host there controls a whole /64
//! and rotating inside it costs nothing. The pair (`pair:`) is one account
//! as seen from one client. The account (`account:`) counts every failure
//! against a threshold [`ACCOUNT_THRESHOLD_FACTOR`] times higher, so a
//! guess spread over many clients, each too few to be banned, still ends in
//! a ban, while one client alone cannot lock an account out for everyone: it
//! is stopped by its own counters long before.
//!
//! The store is **fail open on database errors**: a connection hiccup must
//! never block mail, so every public method returns the safe answer (`None`
//! for a ban check, `()` for a record/clear) and logs once per minute while
//! bumping the `database_unavailable` counter. The reputation screen, the
//! one place this discipline already lives, follows the same rule.
//!
//! Times travel as Unix-seconds (`u64`); the SQL bindings cast them to
//! `timestamptz` via `to_timestamp` so the store does not pull a chrono
//! or `time` dependency.

use std::net::IpAddr;
use std::time::Duration;

/// The active ban for a subject: when it expires and the rule that fired it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanInfo {
	/// The Unix timestamp (seconds) the ban ends; the directory refuses
	/// every authentication for this subject while `now < until_secs`.
	pub until_secs: u64,
	/// The rule that fired the ban, kept verbatim for the audit log
	/// (`auth.banned` event). The wire reply never includes it.
	pub reason: String,
}

/// The ban policy. Holds the four numbers that drive the backoff so the
/// unit tests can shrink the rolling window and the 24-hour cap to seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BanPolicy {
	/// The rolling window (seconds) used to count failures: failures
	/// outside the window do not contribute to the threshold.
	pub window_secs: u64,
	/// The number of failures within the rolling window that fires a ban.
	pub threshold: u32,
	/// The base ban duration. The first ban is `base_secs` long, the next
	/// is `base_secs * 2`, then `base_secs * 4`, etc.
	pub base_secs: u64,
	/// The maximum ban duration, regardless of how many bans have stacked.
	pub max_secs: u64,
}

impl Default for BanPolicy {
	fn default() -> Self {
		Self {
			// The product context's defaults: 15 minutes, 5 failures, base
			// 15 minutes, capped at 24 hours.
			window_secs: 15 * 60,
			threshold: 5,
			base_secs: 15 * 60,
			max_secs: 24 * 60 * 60,
		}
	}
}

/// How many times the client threshold the account subject needs. An account
/// is attacked from many clients at once, and one client alone must not be able
/// to fire its ban: a single client is stopped by its own counters after
/// `threshold` failures, so it can never reach `ACCOUNT_THRESHOLD_FACTOR`
/// times as many inside one window.
pub const ACCOUNT_THRESHOLD_FACTOR: u32 = 4;

/// How many times the client threshold an IPv6 /48 needs. Rotating through the
/// /64s of one allocation gives each /64 its own free attempts, and this is
/// what adds them up; it is high because a /48 can hold many unrelated users
/// (a hosting provider, an office, a campus).
pub const NET_THRESHOLD_FACTOR: u32 = 8;

impl BanPolicy {
	/// The failures within the window that fire a ban for `subject`: the plain
	/// threshold for a client or a pair, [`ACCOUNT_THRESHOLD_FACTOR`] times it
	/// for an account.
	pub fn threshold_for(&self, subject: &str) -> u32 {
		if subject.starts_with("account:") {
			self.threshold.saturating_mul(ACCOUNT_THRESHOLD_FACTOR)
		} else if subject.starts_with("net:") {
			self.threshold.saturating_mul(NET_THRESHOLD_FACTOR)
		} else {
			self.threshold
		}
	}

	/// How long the next ban lasts given the current `strikes` count. The
	/// first ban (strikes = 1) is `base_secs`; each subsequent ban doubles
	/// it, capped at `max_secs`. Saturates the exponent at 20 so the
	/// shift cannot overflow.
	pub fn duration_for(&self, strikes: u32) -> Duration {
		let exponent = strikes.saturating_sub(1).min(20);
		let multiplier = 1u64 << exponent;
		let secs = self.base_secs.saturating_mul(multiplier).min(self.max_secs);
		Duration::from_secs(secs)
	}
}

/// The ban store interface consulted by every listener. The production
/// implementation is [`PgBanStore`] (PostgreSQL-backed); the unit tests
/// use an in-memory fake that shares the trait surface so a listener
/// test can swap it in and assert a banned subject never reaches the
/// password verifier. The directory holds an
/// `Option<Arc<dyn BanStore>>` so a deployment without `[database]`
/// degrades to the per-connection three-strikes counters.
pub trait BanStore: std::fmt::Debug + Send + Sync {
	/// Record one authentication failure for `subject` on `protocol` at
	/// `now_secs` (Unix seconds).
	fn record_failure(
		&self,
		subject: &str,
		protocol: &str,
		now_secs: u64,
	) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>>;

	/// Whether `subject` is currently banned. `None` when the subject is
	/// clean, or when the lookup failed (fail open).
	fn is_banned(
		&self,
		subject: &str,
		now_secs: u64,
	) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<BanInfo>> + Send + '_>>;

	/// A successful authentication clears the ban and the failure
	/// history for `subject`.
	fn clear_success(
		&self,
		subject: &str,
	) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>>;

	/// Whether the operator's allow list covers `ip`. An allow-listed client
	/// is never counted and never banned. The default is "not listed", which
	/// is right for a store that has no allow list.
	fn is_allow_listed(
		&self,
		_ip: IpAddr,
	) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + '_>> {
		Box::pin(async { false })
	}

	/// Drop failures older than 24 hours and bans whose `until` is older
	/// than 24 hours ago.
	fn sweep(
		&self,
		now_secs: u64,
	) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>>;

	/// Drop every row for `account`, called from
	/// [`crate::directory_store::removal::remove_account`].
	fn remove_account(
		&self,
		account: &str,
	) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>>;
}

/// Build the canonical `'ip:<addr>'` subject for `ip`.
pub fn subject_ip(ip: IpAddr) -> String {
	format!("ip:{ip}")
}

/// The part of a client address that identifies the client for counting: the
/// address itself for IPv4, the /64 network for IPv6.
fn client_key(ip: IpAddr) -> String {
	match ip {
		IpAddr::V4(v4) => v4.to_string(),
		IpAddr::V6(v6) => {
			let mut octets = v6.octets();
			octets[8..].fill(0);
			std::net::Ipv6Addr::from(octets).to_string()
		}
	}
}

/// The `ip:` subject failures from `ip` are counted on: the address for IPv4,
/// the /64 for IPv6.
pub fn subject_client(ip: IpAddr) -> String {
	format!("ip:{}", client_key(ip))
}

/// The `net:<prefix>` subject an IPv6 client's failures also count on: its
/// /48. `None` for IPv4, where the address is already as wide as it gets.
pub fn subject_net(ip: IpAddr) -> Option<String> {
	let IpAddr::V6(v6) = ip else {
		return None;
	};
	let mut octets = v6.octets();
	octets[6..].fill(0);
	Some(format!("net:{}/48", std::net::Ipv6Addr::from(octets)))
}

/// The `pair:<login>|<client>` subject for one account seen from one client
/// (see [`subject_client`] for what a client is). Without a client address
/// every attempt on the account shares the client `unknown`, so the pair still
/// stops guessing at the base threshold.
pub fn subject_pair(account: &str, ip: Option<IpAddr>) -> String {
	let client = ip.map_or_else(|| "unknown".to_string(), client_key);
	format!("pair:{}|{client}", account.to_ascii_lowercase())
}

/// Build the canonical `'account:<login>'` subject for `account`.
pub fn subject_account(account: &str) -> String {
	format!("account:{}", account.to_ascii_lowercase())
}

#[path = "bans_sql.rs"]
mod sql;
pub use sql::{BanRow, BanTarget, MANUAL_REASON, PgBanStore, parse_allow};

#[cfg(test)]
#[path = "bans_tests.rs"]
pub(crate) mod tests;
