//! Per-listener rate-limit state shared across SMTP listeners. Pulled out
//! of `serve` because the three limiters (submission, inbound IP,
//! inbound sender) are wired from three different config sections and
//! each one was a multi-line `if let`/`map` block, all sitting next to
//! each other with the only thing in common being "shared by every
//! listener".

use std::sync::Arc;

use crate::config::Config;
use crate::smtp::ratelimit::{InboundLimit, SendLimiter};

/// The three rate limiters `serve` needs to attach to each SMTP listener.
/// Created whenever the matching `[server] submission_rate_limit_per_min`
/// or `[server] inbound_rate_limit_*` section is configured; `None`
/// disables the corresponding check at MAIL FROM time.
pub(super) struct RateLimiters {
	/// Optional per-account submission rate limiter.
	pub send_limiter: Option<Arc<SendLimiter>>,
	/// Optional per-client-IP inbound rate limiter.
	pub inbound_ip_limit: Option<InboundLimit>,
	/// Optional per-envelope-sender inbound rate limiter.
	pub inbound_sender_limit: Option<InboundLimit>,
}

/// Build the three limiters from `config`. A limiter is created only when
/// the matching `[server]` field is set, so an unset section leaves the
/// corresponding `RateLimiters` field at `None` and the listener wiring
/// skips the check at MAIL FROM time.
pub(super) fn build_rate_limiters(config: &Config) -> RateLimiters {
	let has_any_submission_limit = config.submission_rate_limit_per_min.is_some()
		|| !config.domain_submission_limits.is_empty();
	let send_limiter = has_any_submission_limit.then(|| Arc::new(SendLimiter::new(60)));
	let inbound_ip_limit = config
		.inbound_rate_limit_per_ip_per_min
		.map(|per_min| InboundLimit {
			limiter: Arc::new(SendLimiter::new(60)),
			per_min,
		});
	let inbound_sender_limit =
		config
			.inbound_rate_limit_per_sender_per_min
			.map(|per_min| InboundLimit {
				limiter: Arc::new(SendLimiter::new(60)),
				per_min,
			});
	RateLimiters {
		send_limiter,
		inbound_ip_limit,
		inbound_sender_limit,
	}
}
