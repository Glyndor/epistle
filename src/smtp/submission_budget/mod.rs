//! The submission rate limits a message is charged against, in one place
//! for SMTP, `POST /api/v1/send` and JMAP `EmailSubmission/set`.
//!
//! Every limit that covers the authenticated account is collected into a
//! [`Budget`]: the per-account limit (its domain's override, else the
//! server-wide default) and the aggregate limit of every tenant that owns
//! one of its addresses. The keys are the account name and the tenant
//! name, both taken from what the server authenticated, never from the
//! envelope or the headers. The limiters are the same `Arc`s on the three
//! protocols, so switching protocol, credential or sender address does not
//! open a second budget.
//!
//! A message costs one unit per recipient and is charged once, when it is
//! accepted: all limits or none ([`Budget::charge`]). A charge whose
//! message is then refused is given back ([`Charge::refund`]), so a refused
//! or failed submission costs nothing.

use std::sync::Arc;

use super::ratelimit::SendLimiter;
use crate::api::TenantLimits;

/// The text of every refusal by a submission rate limit: the SMTP `450
/// 4.7.1` line, the REST `429` message and the JMAP `rateLimit`
/// description. It names no tenant, account or number.
pub const RATE_LIMITED: &str = "sending rate limit exceeded; retry later";

/// One limit a submission is charged against.
#[derive(Debug)]
struct Limit {
	limiter: Arc<SendLimiter>,
	key: String,
	per_min: u32,
}

/// Every submission limit that applies to one account.
#[derive(Debug, Default)]
pub struct Budget {
	limits: Vec<Limit>,
}

/// A submission that would go over one of its limits.
#[derive(Debug, PartialEq, Eq)]
pub struct OverLimit;

impl Budget {
	/// The limits of `account`: `account_limit` (its limiter and resolved
	/// per-minute cap) when one applies, then every tenant of `tenants`
	/// that owns one of the account's addresses. `addresses` is only
	/// called when some tenant has a rate limit.
	pub fn for_account(
		account: &str,
		account_limit: Option<(&Arc<SendLimiter>, u32)>,
		tenants: Option<&TenantLimits>,
		addresses: impl FnOnce() -> Vec<String>,
	) -> Self {
		let mut limits = Vec::new();
		if let Some((limiter, per_min)) = account_limit {
			limits.push(Limit {
				limiter: Arc::clone(limiter),
				key: account.to_string(),
				per_min,
			});
		}
		if let Some(tenants) = tenants.filter(|tenants| tenants.has_rate_limits()) {
			for (limiter, key, per_min) in tenants.submission_limiters(&addresses()) {
				limits.push(Limit {
					limiter,
					key,
					per_min,
				});
			}
		}
		Budget { limits }
	}

	/// Whether one more recipient fits under every limit at `now`. Charges
	/// nothing: SMTP asks at `MAIL FROM`, before the message is sent.
	pub fn has_room(&self, now: u64) -> bool {
		self.limits
			.iter()
			.all(|limit| limit.limiter.has_room(&limit.key, 1, limit.per_min, now))
	}

	/// Charge `recipients` units against every limit, or none when any of
	/// them would go over. The returned [`Charge`] is refunded when the
	/// message is not accepted after all.
	pub fn charge(&self, recipients: u32, now: u64) -> Result<Charge, OverLimit> {
		let mut charge = Charge {
			charged: Vec::new(),
			count: recipients,
			now,
		};
		for limit in &self.limits {
			if !limit
				.limiter
				.check_n(&limit.key, recipients, limit.per_min, now)
			{
				charge.refund();
				return Err(OverLimit);
			}
			charge
				.charged
				.push((Arc::clone(&limit.limiter), limit.key.clone()));
		}
		Ok(charge)
	}
}

/// Units taken by [`Budget::charge`]. Kept when the message is accepted;
/// [`refund`](Self::refund) gives them back when it is not.
#[derive(Debug)]
#[must_use = "a charge is either kept or refunded"]
pub struct Charge {
	charged: Vec<(Arc<SendLimiter>, String)>,
	count: u32,
	now: u64,
}

impl Charge {
	/// Give the units back to every limit charged.
	pub fn refund(self) {
		for (limiter, key) in &self.charged {
			limiter.refund(key, self.count, self.now);
		}
	}
}

/// A [`Charge`] waiting for the message to be accepted: refunded when
/// dropped, unless [`accept`](Self::accept) was called first. The SMTP
/// listener holds one across the post-DATA checks so every refusal (loop,
/// scanner, virus, spool failure, a closed connection) gives it back.
#[derive(Debug)]
pub struct PendingCharge(Option<Charge>);

impl PendingCharge {
	/// Hold `charge` until the message is accepted.
	pub fn new(charge: Option<Charge>) -> Self {
		PendingCharge(charge)
	}

	/// The message was accepted: keep the charge.
	pub fn accept(&mut self) {
		self.0 = None;
	}
}

impl Drop for PendingCharge {
	fn drop(&mut self) {
		if let Some(charge) = self.0.take() {
			charge.refund();
		}
	}
}

#[cfg(test)]
mod tests;
