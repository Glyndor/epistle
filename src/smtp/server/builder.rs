//! The `with_*` builder methods on [`Server`]. They live in their own
//! file so the state-machine implementation in `mod.rs` does not
//! grow past the 500-code-line limit. Every method is a plain
//! `self -> Self` setter.

use std::sync::Arc;

use super::super::directory::Directory;
use super::super::diskspace::DiskGuard;
use super::super::memory_budget::MemoryBudget;
use super::super::ratelimit::{InboundLimit, SendLimiter};
use super::super::sink::MessageSink;
use super::{DirectoryHandle, MAX_CONNECTIONS, MAX_CONNECTIONS_PER_IP, Server, TlsMode};

impl Server {
	/// Create a plaintext server (STARTTLS unavailable). Without
	/// `with_directory` every recipient is rejected (fail closed).
	pub fn new(hostname: &str, sink: Arc<dyn MessageSink>) -> Self {
		Server {
			hostname: hostname.to_string(),
			sink,
			tls: None,
			tls_mode: TlsMode::Opportunistic,
			directory: DirectoryHandle::new(Directory::default()),
			data_dir: None,
			crypto: None,
			spf: None,
			dnsbl: crate::dnsbl::Dnsbl::default(),
			reputation: None,
			bayes: None,
			hook: None,
			llm: None,
			subjectpass: None,
			metrics: Arc::new(crate::metrics::Metrics::new()),
			first_time_delay: std::time::Duration::ZERO,
			report_dir: None,
			arc_sealer: None,
			greylist: None,
			bayes_junk_at: 0.95,
			bayes_reject_at: None,
			oauth: None,
			cbind_data: None,
			send_limiter: None,
			global_submission_rate_limit_per_min: None,
			inbound_ip_limit: None,
			inbound_sender_limit: None,
			tenant_limits: None,
			disk_guard: None,
			drain: None,
			quota: None,
			correspondents: None,
			daily_new_recipients: None,
			max_connections: MAX_CONNECTIONS,
			memory_budget: None,
			max_connections_per_ip: MAX_CONNECTIONS_PER_IP,
			trusted_networks: Vec::new(),
			max_message_size: crate::smtp::session::MAX_MESSAGE_SIZE,
			data_rate: super::DataRate::default(),
			junk_command_limit: crate::smtp::session::DEFAULT_JUNK_COMMAND_LIMIT,
			max_session_time: std::time::Duration::from_secs(super::DEFAULT_MAX_SESSION_TIME_SECS),
			auth_protocol: crate::config::Protocol::Submission,
			scram_enabled: true,
		}
	}

	/// Tag every password authentication attempt through this server with
	/// `protocol` so the directory's per-account `allowed_protocols` set
	/// can admit or reject it. Use the [`Protocol`](crate::config::Protocol) value matching the
	/// listener kind (`Protocol::Submissions` for the implicit-TLS port,
	/// `Protocol::Submission` for STARTTLS submission, `Protocol::Smtp`
	/// for the receiving port, though the latter does not advertise AUTH
	/// so the choice has no practical effect).
	pub fn with_auth_protocol(mut self, protocol: crate::config::Protocol) -> Self {
		self.auth_protocol = protocol;
		self
	}

	/// Attach a shared per-account submission rate limiter.
	pub fn with_send_limiter(mut self, limiter: Arc<SendLimiter>) -> Self {
		self.send_limiter = Some(limiter);
		self
	}

	/// Set the server-wide default submission rate limit (messages/min).
	/// The per-domain limit on the active directory (configured via
	/// [`crate::smtp::directory::Directory::with_domain_submission_limits`])
	/// takes precedence at check time; this is the fallback. `None`
	/// together with no per-domain entry disables submission rate limiting.
	pub fn with_global_submission_rate_limit(mut self, limit: Option<u32>) -> Self {
		self.global_submission_rate_limit_per_min = limit;
		self
	}

	/// Attach a shared per-client-IP inbound rate limiter (msgs/min).
	/// Consumed at `MAIL FROM` for sessions that never authenticated; a
	/// peer IP missing from the listener is skipped, the limit still
	/// applied to the peers that are known.
	pub fn with_inbound_ip_limit(mut self, limit: InboundLimit) -> Self {
		self.inbound_ip_limit = Some(limit);
		self
	}

	/// Attach a shared per-envelope-sender inbound rate limiter (msgs/min).
	/// Consumed at `MAIL FROM` for sessions that never authenticated; the
	/// null sender (`<>`) used by bounces is always skipped.
	pub fn with_inbound_sender_limit(mut self, limit: InboundLimit) -> Self {
		self.inbound_sender_limit = Some(limit);
		self
	}

	/// Attach per-tenant aggregate limits. On top of the per-account
	/// limiter; the SMTP path checks both before accepting MAIL FROM.
	pub fn with_tenant_limits(mut self, limits: Arc<crate::api::TenantLimits>) -> Self {
		self.tenant_limits = Some(limits);
		self
	}

	/// Follow `drain`: stop accepting when it starts, let an open
	/// transaction finish, then close with `421`.
	pub fn with_drain(mut self, drain: Arc<crate::shutdown::Drain>) -> Self {
		self.drain = Some(drain);
		self
	}

	/// Attach a shared disk-space guard for `data_dir`. The SMTP path
	/// consults it at `MAIL FROM` and rejects with `452` when the
	/// filesystem cannot hold another message, so the remote retries
	/// instead of receiving `250` for a payload the spool cannot write.
	pub fn with_disk_guard(mut self, guard: Arc<DiskGuard>) -> Self {
		self.disk_guard = Some(guard);
		self
	}

	/// Check local recipients against their mailbox quota: a full mailbox
	/// is refused at `RCPT TO`, one this message would overfill at the end
	/// of DATA (see [`crate::smtp::quota`]).
	pub fn with_quota(mut self, quota: Arc<crate::smtp::quota::MailboxQuota>) -> Self {
		self.quota = Some(quota);
		self
	}

	/// Attach the per-account correspondent store. The end-of-DATA
	/// check consults it for the rolling 24h new-recipient cap. The
	/// store is shared across listeners by way of `Arc`, so a single
	/// `CorrespondentStore::open(data_dir)` is enough.
	pub fn with_correspondents(mut self, store: Arc<crate::storage::CorrespondentStore>) -> Self {
		self.correspondents = Some(store);
		self
	}

	/// Set the rolling 24h cap on first-time recipients per account
	/// (`Config::new_recipients_per_day`). `None` disables the cap.
	/// The cap only fires when a correspondent store has also been
	/// attached; either field alone is a no-op.
	pub fn with_daily_new_recipients(mut self, limit: Option<u32>) -> Self {
		self.daily_new_recipients = limit;
		self
	}

	/// Cap concurrent connections for this listener (0 keeps the default).
	pub fn with_max_connections(mut self, max: usize) -> Self {
		if max > 0 {
			self.max_connections = max;
		}
		self
	}

	/// Cap concurrent connections per client IP for this listener (0
	/// keeps the built-in default). A peer over the cap is answered
	/// `421 4.7.0 too many connections from your address` and closed;
	/// a peer on a [`Self::with_trusted_networks`] CIDR is exempt.
	pub fn with_max_connections_per_ip(mut self, max: usize) -> Self {
		if max > 0 {
			self.max_connections_per_ip = max;
		}
		self
	}

	/// CIDR blocks exempt from the per-IP connection cap. A peer whose
	/// address matches any CIDR bypasses the per-IP check; the global
	/// per-listener cap still applies. An empty list (the default)
	/// makes every peer subject to the per-IP cap.
	pub fn with_trusted_networks(mut self, cidrs: Vec<crate::cidr::Cidr>) -> Self {
		self.trusted_networks = cidrs;
		self
	}

	/// Share the per-listener byte budget with every session. The
	/// budget draws from itself on every DATA line and every BDAT
	/// chunk; the reservation is released on every path that drops
	/// the in-flight body. `None` (the default) leaves the historical
	/// unbounded behaviour in place.
	pub fn with_memory_budget(mut self, budget: Arc<MemoryBudget>) -> Self {
		self.memory_budget = Some(budget);
		self
	}

	/// Set the per-instance message-size cap for every session opened
	/// on this listener. The cap is advertised in EHLO, enforced at
	/// `MAIL FROM` (SIZE parameter), at end-of-DATA, and per BDAT chunk.
	/// `0` keeps the built-in default
	/// ([`crate::smtp::session::MAX_MESSAGE_SIZE`]).
	pub fn with_max_message_size(mut self, bytes: usize) -> Self {
		if bytes > 0 {
			self.max_message_size = bytes;
		}
		self
	}

	/// Hold every message transaction on this listener to `rate`: the
	/// minimum average transfer rate once its grace period is over. A
	/// floor of `0` turns the check off.
	pub fn with_data_rate(mut self, rate: super::DataRate) -> Self {
		self.data_rate = rate;
		self
	}

	/// Close a session on this listener after `limit` commands that bring
	/// it no closer to a delivered message (`0` turns the limit off).
	pub fn with_junk_command_limit(mut self, limit: u32) -> Self {
		self.junk_command_limit = limit;
		self
	}

	/// Close a session on this listener once it is older than `limit`, at
	/// the next command boundary (never while a message body is being
	/// received). Zero turns the limit off.
	pub fn with_max_session_time(mut self, limit: std::time::Duration) -> Self {
		self.max_session_time = limit;
		self
	}

	/// Provide the `tls-server-end-point` certificate hash, enabling
	/// SCRAM-SHA-256-PLUS once a session is inside TLS.
	pub fn with_channel_binding(mut self, cert_hash: crate::tls::EndPoint) -> Self {
		self.cbind_data = Some(cert_hash);
		self
	}

	/// Accept OAUTHBEARER/XOAUTH2 bearer tokens, verified by `verifier`.
	pub fn with_oauth(mut self, verifier: Arc<crate::oauth::OauthVerifier>) -> Self {
		self.oauth = Some(verifier);
		self
	}

	/// Toggle the `[auth] scram` knob for this listener. `false` hides
	/// SCRAM-SHA-256 and SCRAM-SHA-256-PLUS on the wire and refuses an
	/// explicit `AUTH` against them; PLAIN and LOGIN stay in.
	pub fn with_scram_enabled(mut self, enabled: bool) -> Self {
		self.scram_enabled = enabled;
		self
	}

	/// Seal inbound unauthenticated mail into its ARC chain (RFC 8617).
	pub fn with_arc_sealer(mut self, sealer: Arc<crate::arc::sealer::ArcSealer>) -> Self {
		self.arc_sealer = Some(sealer);
		self
	}

	/// Greylist unseen triplets, deferring them for `delay_secs` seconds.
	/// The store can be either backing (`MemoryGreylist` or `PgGreylistStore`);
	/// they implement the same trait.
	pub fn with_greylist(
		mut self,
		store: Arc<dyn crate::antispam::greylist::GreylistStore>,
		delay_secs: u64,
	) -> Self {
		self.greylist = Some((store, delay_secs));
		self
	}

	/// Set the Bayesian thresholds that decide on their own before the
	/// uncertain band: any unauthenticated message whose score lands at or
	/// above `junk_at` is delivered to the recipient's Junk mailbox;
	/// any whose score lands at or above `reject_at` is refused with
	/// `550 5.7.1`. `reject_at` must be at least `junk_at` so the rejected
	/// band is a subset of the junked one. Authenticated sessions ignore
	/// both; an under-trained corpus ignores both.
	pub fn with_bayes_thresholds(mut self, junk_at: f64, reject_at: Option<f64>) -> Self {
		self.bayes_junk_at = junk_at;
		self.bayes_reject_at = reject_at;
		self
	}

	/// Share a metrics registry across listeners and the metrics endpoint.
	pub fn with_metrics(mut self, metrics: Arc<crate::metrics::Metrics>) -> Self {
		self.metrics = metrics;
		self
	}

	/// Consult an external scanner hook for unauthenticated inbound mail.
	pub fn with_hook(mut self, hook: Arc<dyn crate::antispam::hook::MailHook>) -> Self {
		self.hook = Some(hook);
		self
	}

	/// Consult the LLM hook for unauthenticated mail whose Bayesian score
	/// lands in the configured uncertain band. Outside the band the hook is
	/// not called at all.
	pub fn with_llm(mut self, llm: crate::antispam::llm::LlmHook) -> Self {
		self.llm = Some(llm);
		self
	}

	/// Record sender reputation for accepted unauthenticated mail.
	pub fn with_reputation_pool(mut self, pool: sqlx::PgPool) -> Self {
		self.reputation = Some(pool);
		self
	}

	/// Train the (encrypted-at-rest) Bayesian corpus on accept/reject decisions.
	pub fn with_bayes(
		mut self,
		store: std::sync::Arc<dyn crate::antispam::corpus::BayesScorer>,
	) -> Self {
		self.bayes = Some(store);
		self
	}

	/// Enable SubjectPass: messages in the uncertain Bayesian band that lack a
	/// valid token and cannot be resolved by an LLM hook are refused with a
	/// freshly minted token the sender can put in the subject. The validator
	/// refuses to enable it without a `[database]` section.
	pub fn with_subjectpass(mut self, pass: crate::antispam::subjectpass::SubjectPass) -> Self {
		self.subjectpass = Some(pass);
		self
	}

	/// Delay first-time unauthenticated senders by `secs` seconds. Zero (the
	/// default) disables the slowdown.
	pub fn with_first_time_delay(mut self, secs: u64) -> Self {
		self.first_time_delay = std::time::Duration::from_secs(secs);
		self
	}

	/// Enable SPF verification of unauthenticated inbound mail.
	pub fn with_spf(mut self, dns: Arc<dyn crate::spf::DnsLookup>) -> Self {
		self.spf = Some(dns);
		self
	}
}
