//! Per-listener rate-limit state shared across SMTP listeners. Pulled out
//! of `serve` because the three limiters (submission, inbound IP,
//! inbound sender) are wired from three different config sections and
//! each one was a multi-line `if let`/`map` block, all sitting next to
//! each other with the only thing in common being "shared by every
//! listener".

use std::sync::Arc;

use crate::config::Config;
use crate::smtp::ratelimit::{InboundLimit, SendLimiter};
use crate::smtp::server::Server;

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
	// Keyed by authenticated account: never refuses an account for map
	// size and never resets a running window (see `for_authenticated_keys`).
	let send_limiter =
		has_any_submission_limit.then(|| Arc::new(SendLimiter::for_authenticated_keys(60)));
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

/// Apply the per-account, per-domain and per-tenant submission limits
/// to `server`. This is the production single wiring point: both
/// `serve::serve`'s listener loop and the regression test in
/// `serve_tests_ratelimit.rs` go through this helper so the
/// per-account cap, the per-domain cap and the tenant aggregate cap
/// never drift apart again.
///
/// The helper attaches the limiter (built once and shared across the
/// listeners), the server-wide default, and the tenant aggregate
/// state. The directory itself is constructed by
/// `directory_store::AccountStore::open` and rebuilt every time the
/// static config changes; that helper is what surfaces the per-domain
/// entries to the `Directory` consulted at MAIL FROM time.
pub(super) fn wire_smtp_submission_limits(
	server: Server,
	config: &Config,
	send_limiter: &Option<Arc<SendLimiter>>,
	tenant_limits: Option<&Arc<crate::api::TenantLimits>>,
) -> Server {
	let mut server = server;
	if let Some(limiter) = send_limiter {
		server = server.with_send_limiter(Arc::clone(limiter));
	}
	server = server.with_global_submission_rate_limit(config.submission_rate_limit_per_min);
	if let Some(limits) = tenant_limits {
		server = server.with_tenant_limits(Arc::clone(limits));
	}
	server
}

/// Give the API (`POST /api/v1/send`, JMAP `EmailSubmission/set`) the same
/// submission limiters as the SMTP listeners: the per-account limiter with
/// the server-wide cap, and the tenant limits. One budget per account and
/// per tenant whatever the protocol.
pub(super) fn wire_api_submission_limits(
	state: crate::api::ApiState,
	config: &Config,
	send_limiter: &Option<Arc<SendLimiter>>,
	tenant_limits: &Arc<crate::api::TenantLimits>,
) -> crate::api::ApiState {
	state
		.with_tenant_limits(Arc::clone(tenant_limits))
		.with_submission_limit(send_limiter.clone(), config.submission_rate_limit_per_min)
}
