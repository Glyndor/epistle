//! The submission rate limits on `POST /api/v1/send` and JMAP
//! `EmailSubmission/set`: the same per-account limiter and tenant limiters
//! the SMTP listeners charge, so a sender has one budget whatever the
//! protocol, credential or sender address it uses.

use std::sync::Arc;

use super::ApiState;
use crate::smtp::ratelimit::SendLimiter;
use crate::smtp::submission_budget::Budget;

impl ApiState {
	/// Share the per-account submission `limiter` the SMTP listeners use,
	/// with the server-wide per-account cap `default_per_min` (a domain's
	/// `domain_submission_limits` entry wins over it). `None` leaves the
	/// per-account limit off, as on SMTP. Must be set before the state is
	/// shared.
	pub fn with_submission_limit(
		mut self,
		limiter: Option<Arc<SendLimiter>>,
		default_per_min: Option<u32>,
	) -> Self {
		if let Some(inner) = Arc::get_mut(&mut self.inner) {
			inner.submission_limit = limiter.map(|limiter| (limiter, default_per_min));
		}
		self
	}

	/// The submission limits of `account`, which the caller has already
	/// authorized: its per-account limit and every tenant owning one of
	/// its addresses, or one of `known`, addresses the caller checked the
	/// account owns.
	pub(crate) fn submission_budget(&self, account: &str, known: &[String]) -> Budget {
		let directory = self.directory_snapshot();
		let account_limit = self
			.inner
			.submission_limit
			.as_ref()
			.and_then(|(limiter, default)| {
				directory
					.as_ref()
					.and_then(|directory| directory.submission_limit_for(account))
					.or(*default)
					.map(|per_min| (limiter, per_min))
			});
		Budget::for_account(account, account_limit, Some(self.tenant_limits()), || {
			let mut addresses = directory
				.as_ref()
				.map(|directory| directory.addresses_for(account))
				.unwrap_or_default();
			for address in known {
				if !addresses
					.iter()
					.any(|seen| seen.eq_ignore_ascii_case(address))
				{
					addresses.push(address.clone());
				}
			}
			addresses
		})
	}
}
