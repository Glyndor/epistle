//! The forwarding guard: where the copies an account's mail makes on its
//! own may go, and how many of them the account and the server send.
//!
//! Local delivery asks the guard about every copy before it queues it: the
//! addresses an account forwards to, the targets of a Sieve `redirect` and
//! the sender a vacation reply goes to. A copy the policy refuses is not
//! queued and the delivery keeps the message in the mailbox instead, so a
//! refusal never loses mail. A batch the limits refuse is refused whole,
//! and charges nothing.
//!
//! What the guard does not decide stays fixed: bounces are never
//! forwarded, a message that names an address already in `Delivered-To` is
//! refused as a loop, the hop limit stops a chain across accounts, and
//! every copy leaves with SRS and ARC. The settings come from
//! `[forwarding]` and the scopes in [`crate::antispam::scopes`].

use std::sync::Arc;

use crate::antispam::scopes::{ForwardSettings, Scopes, Target};
use crate::config::{Config, ForwardPolicy};
use crate::smtp::ratelimit::WindowLimiter;

/// The window the per-minute limits count in.
const WINDOW_SECS: u64 = 60;
/// The key the server-wide count is kept under, in a limiter of its own.
const SERVER_KEY: &str = "server";

/// The settings and the counters of the forwarding guard.
#[derive(Debug)]
pub struct Guard {
	policy: ForwardPolicy,
	scopes: Arc<Scopes>,
	account_per_min: Option<u32>,
	server_per_min: Option<u32>,
	submission_default: Option<u32>,
	accounts: WindowLimiter,
	server: WindowLimiter,
}

impl Guard {
	/// The guard `config` asks for, resolving scopes through `scopes`.
	pub fn from_config(config: &Config, scopes: Arc<Scopes>) -> Self {
		Self {
			policy: config.forwarding.policy,
			scopes,
			account_per_min: config.forwarding.account_per_min,
			server_per_min: config.forwarding.server_per_min,
			submission_default: config.submission_rate_limit_per_min,
			accounts: WindowLimiter::for_authenticated_keys(WINDOW_SECS),
			server: WindowLimiter::new(WINDOW_SECS),
		}
	}

	/// The settings for mail delivered to `account` at an address of
	/// `domain`.
	pub fn settings(&self, account: &str, domain: &str) -> ForwardSettings {
		let target = Target {
			domain: domain.to_string(),
			account: Some(account.to_string()),
		};
		self.scopes.forward_settings(&target, self.policy)
	}

	/// The addresses among `targets` that the policy of `account` (at an
	/// address of `domain`) lets a copy go to, and how many it refused.
	/// `hosted` says whether a domain is one this server hosts.
	pub fn permitted(
		&self,
		(account, domain): (&str, &str),
		targets: Vec<String>,
		hosted: impl Fn(&str) -> bool,
	) -> (Vec<String>, usize) {
		let policy = self.settings(account, domain).policy;
		let total = targets.len();
		let allowed: Vec<String> = targets
			.into_iter()
			.filter(|address| {
				let address_domain = address.rsplit_once('@').map_or("", |(_, d)| d);
				policy.allows(hosted(address_domain))
			})
			.collect();
		let refused = total - allowed.len();
		(allowed, refused)
	}

	/// Charge `count` copies to `account` and to the server at `now` (epoch
	/// seconds), and say whether they all fit. All or nothing: a batch that
	/// does not fit charges nothing to the side that refused it.
	/// `submission_limit` is the account's own submission limit, the
	/// fallback when no forwarding limit is set.
	pub fn charge(
		&self,
		(account, domain): (&str, &str),
		count: usize,
		submission_limit: Option<u32>,
		now: u64,
	) -> bool {
		if count == 0 {
			return true;
		}
		let count = u32::try_from(count).unwrap_or(u32::MAX);
		let account_limit = self
			.settings(account, domain)
			.per_min
			.or(self.account_per_min)
			.or(submission_limit)
			.or(self.submission_default);
		account_limit.is_none_or(|limit| self.accounts.check_n(account, count, limit, now))
			&& self
				.server_per_min
				.is_none_or(|limit| self.server.check_n(SERVER_KEY, count, limit, now))
	}
}

#[cfg(test)]
mod tests;
