//! Builder-style `with_*` methods and setters that wire collaborators and
//! limits into a [`Session`].

use std::sync::Arc;

use super::{Directory, DiskGuard, MemoryBudget, Session, cap};

// In scope for the intra-doc links of the methods below.
#[allow(unused_imports)]
use super::{DEFAULT_MAX_RECIPIENTS, MAX_MAX_RECIPIENTS, MAX_MESSAGE_SIZE, MIN_MAX_RECIPIENTS};

impl Session {
	/// Set the per-instance message-size cap. The same value is used by
	/// the `SIZE` extension in EHLO, the running total checked in
	/// `data_line`, the final size check on end-of-DATA, the per-chunk
	/// cap on BDAT, and the `MAIL FROM` SIZE parameter check. The
	/// default is [`MAX_MESSAGE_SIZE`] when this builder is not used.
	pub fn with_max_message_size(mut self, bytes: usize) -> Self {
		self.max_message_size = bytes;
		self
	}

	/// Set how many recipients one transaction may name. `0` keeps
	/// [`DEFAULT_MAX_RECIPIENTS`]; any other value is taken as given, the
	/// configuration having kept it within [`MIN_MAX_RECIPIENTS`] and
	/// [`MAX_MAX_RECIPIENTS`].
	pub fn with_max_recipients(mut self, count: usize) -> Self {
		if count > 0 {
			self.max_recipients = count;
		}
		self
	}

	/// Attach the shared byte budget. `None` (the default) keeps the
	/// historical unbounded behaviour. With a budget set, every DATA
	/// line and every BDAT chunk tries to reserve its bytes; the
	/// reservation is released on every path that drops the in-flight
	/// body (success, error, RSET, disconnect, panic).
	pub fn with_memory_budget(mut self, budget: Arc<MemoryBudget>) -> Self {
		self.memory_budget = Some(budget);
		self
	}

	/// Whether this session has a memory budget wired in. Useful for
	/// tests and for assertions.
	pub fn has_memory_budget(&self) -> bool {
		self.memory_budget.is_some()
	}

	/// Tag every password authentication attempt through this session with
	/// `protocol` so the directory's per-account `allowed_protocols` set
	/// can admit or reject it. `Protocol::Submission` is the default and
	/// matches the historical behaviour for SMTP AUTH.
	pub fn with_auth_protocol(mut self, protocol: crate::config::Protocol) -> Self {
		self.auth_protocol = protocol;
		self
	}

	/// Set which identification and reputation headers the mail this
	/// session generates gets.
	pub fn with_identification(mut self, policy: crate::smtp::identification::Policy) -> Self {
		self.identification = policy;
		self
	}

	/// Set the verified TLS client-certificate identity (email), enabling SASL
	/// EXTERNAL for this connection. Called by the network layer once a client
	/// presented a certificate that rustls verified against the trust anchor.
	pub fn set_client_identity(&mut self, identity: Option<String>) {
		self.client_identity = identity;
	}

	/// Set the client's peer IP, used to enforce app-password CIDR allowlists.
	pub fn set_peer_ip(&mut self, ip: Option<std::net::IpAddr>) {
		self.peer_ip = ip;
	}

	/// Attach the shared metrics handle so session-side rejections (the
	/// inbound per-IP / per-sender rate limits) increment the matching
	/// counter. `None` is a fine default for tests that don't care.
	pub fn with_metrics(mut self, metrics: std::sync::Arc<crate::metrics::Metrics>) -> Self {
		self.metrics = Some(metrics);
		self
	}

	/// Attach a shared per-account submission rate limiter.
	pub fn with_send_limiter(
		mut self,
		limiter: std::sync::Arc<crate::smtp::ratelimit::SendLimiter>,
	) -> Self {
		self.policy = self.policy.with_send_limiter(limiter);
		self
	}

	/// Toggle the `[auth] scram` knob for this listener. `true` keeps the
	/// default behaviour (both SCRAM-SHA-256 and `-PLUS` advertised when
	/// channel binding is available); `false` hides both on the wire and
	/// refuses an explicit `AUTH` against them.
	pub fn with_scram_enabled(mut self, enabled: bool) -> Self {
		self.scram_enabled = enabled;
		self
	}

	/// Set the server-wide default submission rate limit (messages/min).
	/// The per-domain limit on the active directory (set via
	/// [`crate::smtp::directory::Directory::with_domain_submission_limits`])
	/// takes precedence at check time; this is the fallback when the
	/// account's domain has no entry. `None` together with no per-domain
	/// entry means no limit at all.
	pub fn with_global_submission_rate_limit(mut self, limit: Option<u32>) -> Self {
		self.policy = self.policy.with_global_submission_rate_limit(limit);
		self
	}

	/// Attach a shared per-client-IP inbound rate limiter and its
	/// per-minute cap. Consumed at `MAIL FROM` when the session never
	/// authenticated and a peer IP is known; absent or unknown peer means
	/// the check is skipped.
	pub fn with_inbound_ip_limit(
		mut self,
		limiter: std::sync::Arc<crate::smtp::ratelimit::SendLimiter>,
		per_min: u32,
	) -> Self {
		self.policy = self.policy.with_inbound_ip_limit(limiter, per_min);
		self
	}

	/// Attach a shared per-envelope-sender inbound rate limiter and its
	/// per-minute cap. Consumed at `MAIL FROM` when the session never
	/// authenticated and the reverse path is non-empty; the null sender
	/// (`<>`) used by bounces is always skipped.
	pub fn with_inbound_sender_limit(
		mut self,
		limiter: std::sync::Arc<crate::smtp::ratelimit::SendLimiter>,
		per_min: u32,
	) -> Self {
		self.policy = self.policy.with_inbound_sender_limit(limiter, per_min);
		self
	}

	/// Attach per-tenant aggregate limits. On top of the per-account
	/// limiter in [`Self::with_send_limiter`]; the SMTP path checks both
	/// before accepting MAIL FROM. `None` (the default) is the identity and
	/// short-circuits every check.
	pub fn with_tenant_limits(mut self, limits: std::sync::Arc<crate::api::TenantLimits>) -> Self {
		self.policy = self.policy.with_tenant_limits(limits.clone());
		self.tenant_limits = Some(limits);
		self
	}

	/// Provide the `tls-server-end-point` channel-binding data (the server
	/// certificate hash), enabling SCRAM-SHA-256-PLUS. Set by the network layer
	/// once the connection is TLS.
	pub fn with_channel_binding(mut self, cert_hash: Vec<u8>) -> Self {
		self.cbind_data = Some(cert_hash);
		self
	}

	/// Attach a shared disk-space guard for `data_dir`. When set, `MAIL FROM`
	/// is rejected with `452` if the filesystem cannot hold another message,
	/// so the remote retries instead of accepting a message that will
	/// fail to land in the spool.
	pub fn with_disk_guard(mut self, guard: Arc<DiskGuard>) -> Self {
		self.policy = self.policy.with_disk_guard(guard);
		self
	}

	/// Check local recipients against their mailbox quota (see
	/// [`crate::smtp::quota`]).
	pub fn with_quota(mut self, quota: Arc<crate::smtp::quota::MailboxQuota>) -> Self {
		self.policy = self.policy.with_quota(quota);
		self
	}

	/// Replace the cap state (correspondent store, daily limit, metrics
	/// handle). Wired by the listener at session-construction time so
	/// the end-of-DATA check has the configured pair in scope.
	pub fn with_cap(mut self, cap: cap::Cap) -> Self {
		self.cap = cap;
		self
	}

	/// Mark this session as running inside TLS from the start
	/// (implicit-TLS listeners).
	pub fn with_tls_active(mut self) -> Self {
		self.tls_active = true;
		self
	}

	/// Set the directory used to resolve recipients.
	pub fn with_directory(mut self, directory: Arc<Directory>) -> Self {
		self.directory = directory;
		self
	}

	/// Offer STARTTLS on this session.
	pub fn with_tls_available(mut self) -> Self {
		self.tls_available = true;
		self
	}
}
