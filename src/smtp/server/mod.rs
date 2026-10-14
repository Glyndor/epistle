//! SMTP network layer: accepts connections and drives sessions.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use super::directory::Directory;
use super::diskspace::DiskGuard;
use super::memory_budget::MemoryBudget;
use super::reply::Reply;
use super::session::Session;
use super::sink::MessageSink;
use crate::directory_store::DirectoryHandle;

mod dnsbl_check;
mod run;
mod run_auth;
mod run_band;

/// Read buffer size per connection.
const READ_BUFFER: usize = 4096;

/// Maximum concurrent connections per listener. Excess connections are dropped
/// immediately (TCP RST) to prevent file-descriptor exhaustion.
const MAX_CONNECTIONS: usize = 1000;

/// Maximum concurrent connections per client IP per listener. Excess
/// connections are answered `421 4.7.0 too many connections from your
/// address` and closed (RFC 5321 §4.5.3.2). The cap keeps a single
/// client from monopolising one listener; the global
/// [`MAX_CONNECTIONS`] still bounds the total.
const MAX_CONNECTIONS_PER_IP: usize = 20;

/// Per-read idle timeout. RFC 5321 §4.5.3.2 mandates at least 5 minutes between
/// command-phase reads; we match that minimum to kill Slowloris connections.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(300);

/// Anything the connection loop can read from and write to.
trait Connection: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Connection for T {}

/// What the connection loop is currently reading.
#[derive(Debug, PartialEq, Eq)]
enum Mode {
	Commands,
	Data,
	Auth,
}

/// How a listener treats TLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
	/// Plaintext; STARTTLS offered when an acceptor is configured.
	Opportunistic,
	/// TLS handshake before any SMTP traffic (`submissions`).
	Implicit,
}

/// SMTP server: one instance per listener.
pub struct Server {
	hostname: String,
	sink: Arc<dyn MessageSink>,
	tls: Option<crate::tls::ReloadableAcceptor>,
	tls_mode: TlsMode,
	directory: DirectoryHandle,
	/// On-disk directory where the account mailboxes live; needed to save a
	/// copy of every authenticated submission into the account's `Sent`
	/// folder. `None` disables the save for tests that do not stand up a
	/// real filesystem layout; production wiring in `cli/serve.rs`
	/// always sets it from `config.data_dir`.
	data_dir: Option<std::path::PathBuf>,
	/// At-rest crypto for the mailboxes, used when storing the Sent copy.
	/// Mirrors the crypto the storage layer uses; `None` means "no
	/// at-rest crypto", the same default as the storage layer.
	crypto: Option<Arc<crate::storage::MessageCrypto>>,
	spf: Option<Arc<dyn crate::spf::DnsLookup>>,
	/// DNS blocklist zones to screen unauthenticated clients against.
	dnsbl: crate::dnsbl::Dnsbl,
	/// When set, accepted unauthenticated mail is recorded as ham.
	reputation: Option<sqlx::PgPool>,
	/// When set, the Bayesian corpus is trained on accept/reject decisions.
	bayes: Option<std::sync::Arc<dyn crate::antispam::corpus::BayesScorer>>,
	/// Optional external scanner hook consulted for unauthenticated mail.
	hook: Option<Arc<dyn crate::antispam::hook::MailHook>>,
	/// Optional LLM hook consulted for unauthenticated mail whose Bayesian
	/// score sits inside the configured uncertain band. Outside the band the
	/// classifier is not consulted at all, so a non-`None` value is cheap.
	llm: Option<crate::antispam::llm::LlmHook>,
	/// Optional SubjectPass instance: when set, the server refuses messages
	/// in the uncertain band with `550 5.7.1` and a signed token, and accepts
	/// the resend that carries the matching token in its `Subject:`. The
	/// validator refuses to enable it without a `[database]` section, so
	/// the same Server build only enables it when the Bayesian score is
	/// actually reachable.
	subjectpass: Option<crate::antispam::subjectpass::SubjectPass>,
	/// Shared metrics counters.
	metrics: Arc<crate::metrics::Metrics>,
	/// Delay applied to first-time unauthenticated senders. Zero disables it.
	first_time_delay: std::time::Duration,
	/// If set, DMARC delivery records are written here for aggregate reports.
	report_dir: Option<std::path::PathBuf>,
	/// If set, inbound unauthenticated mail is sealed into its ARC chain.
	arc_sealer: Option<Arc<crate::arc::sealer::ArcSealer>>,
	/// If set, greylist unseen triplets: the store (in-memory or
	/// PostgreSQL-backed) and the delay in seconds. The trait object lets
	/// `serve` swap in the persistent store when `[database]` is configured.
	greylist: Option<(Arc<dyn crate::antispam::greylist::GreylistStore>, u64)>,
	/// Score thresholds for unauthenticated mail whose Bayesian
	/// probability crosses the line:
	/// `junk_at` routes to the Junk mailbox (default 0.95);
	/// `reject_at`, when set, refuses the DATA phase with `550 5.7.1`.
	/// Both are enforced only after the corpus has at least
	/// `MIN_TRUSTED_MESSAGES` on either side, so an empty or under-trained
	/// corpus never junks or rejects. Authenticated sessions bypass both.
	bayes_junk_at: f64,
	bayes_reject_at: Option<f64>,
	/// If set, OAUTHBEARER/XOAUTH2 tokens are accepted, verified by this.
	oauth: Option<Arc<crate::oauth::OauthVerifier>>,
	/// `tls-server-end-point` hash; enables SCRAM-SHA-256-PLUS on TLS sessions.
	cbind_data: Option<crate::tls::EndPoint>,
	/// Whether SCRAM-SHA-256 / SCRAM-SHA-256-PLUS are offered on this
	/// listener (the `[auth] scram` knob). `true` keeps the historical
	/// behaviour; `false` hides both mechanisms on the wire and refuses an
	/// explicit `AUTH` against them. PLAIN/LOGIN stay in.
	scram_enabled: bool,
	/// Shared per-account submission rate limiter for authenticated senders.
	send_limiter: Option<Arc<crate::smtp::ratelimit::SendLimiter>>,
	/// Server-wide default submission rate limit (messages/min) for
	/// authenticated senders. Per-domain limits on the directory win; this
	/// is the fallback when the account's domain has no entry. `None`
	/// together with no per-domain entry disables submission rate limiting.
	global_submission_rate_limit_per_min: Option<u32>,
	/// Shared per-client-IP inbound rate limiter (limiter + cap), consumed
	/// at MAIL FROM by unauthenticated sessions.
	inbound_ip_limit: Option<crate::smtp::ratelimit::InboundLimit>,
	/// Shared per-envelope-sender inbound rate limiter (limiter + cap),
	/// consumed at MAIL FROM by unauthenticated sessions.
	inbound_sender_limit: Option<crate::smtp::ratelimit::InboundLimit>,
	/// Per-tenant aggregate limits (accounts, storage, rate). On top of the
	/// per-account limiter; empty is the identity.
	tenant_limits: Option<Arc<crate::api::TenantLimits>>,
	/// Shared disk-space guard for `data_dir`. `None` disables the check,
	/// which is the right behaviour for tests but not for production: the
	/// production wiring in `cli/serve.rs` always sets it.
	disk_guard: Option<Arc<DiskGuard>>,
	/// The graceful stop this listener follows; none in tests that do not
	/// exercise it.
	drain: Option<Arc<crate::shutdown::Drain>>,
	/// Mailbox quota of local recipients (see [`crate::smtp::quota`]).
	quota: Option<Arc<crate::smtp::quota::MailboxQuota>>,
	/// Per-account correspondent store, consulted at end-of-DATA to
	/// enforce the rolling 24h new-recipient cap. `None` disables the
	/// cap (the default) so the pre-feature behaviour survives in
	/// tests and in production builds that never enable the cap.
	correspondents: Option<Arc<crate::storage::CorrespondentStore>>,
	/// Rolling 24h cap on first-time recipients per account. Pairs with
	/// `correspondents`; either absent disables the cap.
	daily_new_recipients: Option<u32>,
	/// Max concurrent connections for this listener (back-pressure cap).
	max_connections: usize,
	/// Shared byte budget every DATA / BDAT reservation draws from.
	/// `None` (the default) leaves the historical unbounded behaviour
	/// in place; the listener is constructed with `Some` when the
	/// operator configured `[server] message_memory_budget`.
	memory_budget: Option<std::sync::Arc<MemoryBudget>>,
	/// Per-client-IP concurrent connection cap for this listener. A
	/// peer over the cap is answered `421 4.7.0` and closed. The cap
	/// is per-listener: two SMTP listeners each have their own count
	/// for the same IP, so a peer can saturate one listener and still
	/// reach the other. Authenticated submission from a trusted
	/// network is exempt when `[server] trusted_networks` lists the
	/// peer's CIDR.
	max_connections_per_ip: usize,
	/// CIDR blocks exempt from the per-IP connection cap. The set is
	/// per-listener (a `smtp` listener can admit the office while a
	/// `submissions` listener still caps the open internet). Matched
	/// against the client peer; an empty set is the identity.
	trusted_networks: Vec<crate::cidr::Cidr>,
	/// Per-instance message-size cap applied to every session opened
	/// on this listener. The default is
	/// [`crate::smtp::session::MAX_MESSAGE_SIZE`]; raise or lower
	/// with [`Server::with_max_message_size`].
	max_message_size: usize,
	/// The authentication protocol this listener serves. Sessions tag every
	/// password attempt through this server with it, so a per-account
	/// `allowed_protocols` set that does not include the listener's kind
	/// rejects the attempt identically to an unknown login. Default
	/// `Protocol::Submission` matches the historical behaviour (SMTP AUTH
	/// is client submission regardless of the listener's port).
	auth_protocol: crate::config::Protocol,
}

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
			auth_protocol: crate::config::Protocol::Submission,
			scram_enabled: true,
		}
	}

	/// Tag every password authentication attempt through this server with
	/// `protocol` so the directory's per-account `allowed_protocols` set
	/// can admit or reject it. Use the [`Protocol`](crate::config::Protocol) value matching the
	/// listener kind (`Protocol::Submissions` for the implicit-TLS port,
	/// `Protocol::Submission` for STARTTLS submission, `Protocol::Smtp`
	/// for the receiving port — though the latter does not advertise AUTH
	/// so the choice has no practical effect).
	pub fn with_auth_protocol(mut self, protocol: crate::config::Protocol) -> Self {
		self.auth_protocol = protocol;
		self
	}

	/// Attach a shared per-account submission rate limiter.
	pub fn with_send_limiter(mut self, limiter: Arc<crate::smtp::ratelimit::SendLimiter>) -> Self {
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
	pub fn with_inbound_ip_limit(mut self, limit: crate::smtp::ratelimit::InboundLimit) -> Self {
		self.inbound_ip_limit = Some(limit);
		self
	}

	/// Attach a shared per-envelope-sender inbound rate limiter (msgs/min).
	/// Consumed at `MAIL FROM` for sessions that never authenticated; the
	/// null sender (`<>`) used by bounces is always skipped.
	pub fn with_inbound_sender_limit(
		mut self,
		limit: crate::smtp::ratelimit::InboundLimit,
	) -> Self {
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
	pub fn with_memory_budget(mut self, budget: std::sync::Arc<MemoryBudget>) -> Self {
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

	/// Train the Bayesian corpus on a message in the background, when a
	/// reputation/corpus database is configured. Accepted mail trains ham,
	/// rejected mail trains spam, so the classifier learns from the server's
	/// own accept/reject decisions. The no-op default on the trait keeps a
	/// fake scorer (test-only) cheap to wire in.
	fn train_corpus(&self, data: &[u8], spam: bool) {
		if let Some(bayes) = &self.bayes {
			let text = String::from_utf8_lossy(data).into_owned();
			bayes.train(crate::antispam::corpus::SHARED, &text, spam);
		}
	}

	/// Whether the envelope sender is known to **any** local recipient
	/// account of this message (plan 4.6). Returns `(account, sender)`
	/// for the first match so the run-loop can log which account
	/// recognised the sender; the loop only needs to know *whether* the
	/// fast path applies, but the (account, sender) pair is what the
	/// debug log carries so an operator chasing a missed expectation
	/// can see whose correspondent list held the answer.
	///
	/// Recipient-to-account resolution reuses `Directory::resolve`,
	/// the same lookup the SMTP session uses to admit RCPT, so a
	/// domain alias, a multi-target alias, sub-addressing, and the
	/// catch-all all behave identically here.
	///
	/// `None` (no fast path) covers four cases: no correspondent store
	/// wired in, an empty envelope sender (bounce, where greylisting is
	/// also skipped via the unauthenticated check), an unparseable
	/// recipient, or a sender the directory does not recognise as a
	/// local account. The latter is the slow path on purpose: the
	/// sender is not local, so no account owns it, so no correspondent
	/// marker exists for it.
	fn known_correspondent(
		&self,
		message: &crate::smtp::session::AcceptedMessage,
	) -> Option<(String, String)> {
		let store = self.correspondents.as_deref()?;
		// An empty envelope sender is the null reverse path; greylisting
		// is also skipped for it (the inbound is a bounce, not a fresh
		// triplet). The fast path is a no-op there too: the
		// correspondent store is keyed by sender address, and there is
		// none to key on.
		if message.reverse_path.is_empty() {
			return None;
		}
		let sender = message.reverse_path.to_ascii_lowercase();
		let directory = self.directory.current();
		for recipient in &message.recipients {
			let Ok(address) = crate::smtp::address::Address::parse(recipient) else {
				continue;
			};
			let accounts = match directory.resolve(&address) {
				crate::smtp::directory::Resolution::Account(account) => vec![account],
				crate::smtp::directory::Resolution::Alias(accounts) => accounts,
				crate::smtp::directory::Resolution::NotLocal
				| crate::smtp::directory::Resolution::UnknownUser => continue,
			};
			for account in accounts {
				if store.knows(&account, &sender) {
					return Some((account, sender));
				}
			}
		}
		None
	}

	/// Screen unauthenticated clients against the given DNS blocklist zones.
	pub fn with_dnsbl(mut self, dnsbl: crate::dnsbl::Dnsbl) -> Self {
		self.dnsbl = dnsbl;
		self
	}

	/// Enable TLS with the given hot-reloadable acceptor and mode.
	pub fn with_tls(mut self, acceptor: crate::tls::ReloadableAcceptor, mode: TlsMode) -> Self {
		self.tls = Some(acceptor);
		self.tls_mode = mode;
		self
	}

	/// Set the directory handle used to resolve recipients. Sessions
	/// snapshot it at connection start.
	pub fn with_directory(mut self, directory: DirectoryHandle) -> Self {
		self.directory = directory;
		self
	}

	/// Attach the on-disk data directory so the server can save a
	/// copy of every authenticated submission into the account's
	/// `Sent` folder. `None` (the default) disables the save; tests
	/// that do not exercise the feature leave it unset.
	pub fn with_data_dir(mut self, data_dir: std::path::PathBuf) -> Self {
		self.data_dir = Some(data_dir);
		self
	}

	/// Attach the at-rest crypto for the mailboxes; used when
	/// storing the Sent copy so the on-disk encoding matches the
	/// rest of the mailbox. `None` means no at-rest crypto, the
	/// same default the storage layer uses.
	pub fn with_crypto(mut self, crypto: Arc<crate::storage::MessageCrypto>) -> Self {
		self.crypto = Some(crypto);
		self
	}

	/// Enable DMARC aggregate report storage. Delivery records are written
	/// under `data_dir/dmarc-reports/` for later flushing and sending.
	pub fn with_report_dir(mut self, data_dir: std::path::PathBuf) -> Self {
		self.report_dir = Some(data_dir);
		self
	}

	fn new_session(&self) -> Session {
		let mut session = Session::new(&self.hostname)
			.with_directory(self.directory.current())
			.with_auth_protocol(self.auth_protocol)
			.with_metrics(Arc::clone(&self.metrics))
			.with_scram_enabled(self.scram_enabled)
			.with_max_message_size(self.max_message_size);
		if let Some(budget) = &self.memory_budget {
			session = session.with_memory_budget(Arc::clone(budget));
		}
		if let Some(verifier) = &self.oauth {
			session = session.with_oauth(Arc::clone(verifier));
		}
		if let Some(cbind) = &self.cbind_data {
			session = session.with_channel_binding(cbind.current());
		}
		if let Some(limiter) = &self.send_limiter {
			session = session.with_send_limiter(Arc::clone(limiter));
		}
		session =
			session.with_global_submission_rate_limit(self.global_submission_rate_limit_per_min);
		if let Some(ip_limit) = &self.inbound_ip_limit {
			session =
				session.with_inbound_ip_limit(Arc::clone(&ip_limit.limiter), ip_limit.per_min);
		}
		if let Some(sender_limit) = &self.inbound_sender_limit {
			session = session
				.with_inbound_sender_limit(Arc::clone(&sender_limit.limiter), sender_limit.per_min);
		}
		if let Some(guard) = &self.disk_guard {
			session = session.with_disk_guard(Arc::clone(guard));
		}
		if let Some(quota) = &self.quota {
			session = session.with_quota(Arc::clone(quota));
		}
		if let Some(limits) = &self.tenant_limits {
			session = session.with_tenant_limits(Arc::clone(limits));
		}
		// Build the cap state in one go: the listener already holds
		// `correspondents`, `daily_new_recipients`, and a metrics handle;
		// folding them into a `cap::Cap` keeps the session's field
		// surface small (one slot, three sources).
		let mut cap = crate::smtp::session::cap::Cap::empty();
		if let Some(store) = &self.correspondents {
			cap = cap.with_correspondents(Arc::clone(store));
		}
		if self.daily_new_recipients.is_some() {
			cap = cap.with_daily_new_recipients(self.daily_new_recipients);
		}
		cap = cap.with_metrics(Arc::clone(&self.metrics));
		session = session.with_cap(cap);
		session
	}

	/// Accept connections forever. Each connection runs in its own task.
	pub async fn serve(self: Arc<Self>, listener: TcpListener) -> std::io::Result<()> {
		self.serve_on(listener).await
	}

	/// [`Self::serve`] over any source of connections.
	pub(crate) async fn serve_on<A: crate::net::accept::Accept>(
		self: Arc<Self>,
		listener: A,
	) -> std::io::Result<()> {
		let semaphore = Arc::new(Semaphore::new(self.max_connections));
		let per_ip = Arc::new(crate::smtp::per_ip::PerIpCounter::new(
			self.max_connections_per_ip,
		));
		let mut accepting = crate::net::accept::Accepting::new(listener);
		loop {
			let (stream, peer) = match &self.drain {
				Some(drain) => tokio::select! {
					accepted = accepting.next() => accepted,
					() = drain.started() => return Ok(()),
				},
				None => accepting.next().await,
			};
			// A dual-stack `::` listener reports an IPv4 peer as
			// `::ffff:a.b.c.d`; canonicalize before the address reaches
			// SPF, DNSBL, the ban table, the greylist, the inbound rate
			// limit and the audit log so a v4-mapped form cannot slip
			// past an `IpAddr::V4`-typed check anywhere downstream.
			let peer = crate::net::canonical_peer(peer);
			let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() else {
				tracing::warn!(%peer, "SMTP connection limit reached, dropping");
				continue;
			};
			// Per-IP cap. A peer in a trusted CIDR bypasses the cap;
			// the global per-listener semaphore still bounds the
			// total. The accepted branch hands ownership of the
			// counter slot to the connection task: when the task
			// ends, the guard drops, the count decrements, and the
			// next connection from the same IP is admitted.
			let Some(per_ip_slot) = per_ip.try_acquire(peer.ip(), &self.trusted_networks) else {
				tracing::warn!(%peer, "SMTP per-IP connection limit reached, refusing");
				// Best-effort: write the 421 to the wire, then close.
				// The semaphore permit is dropped immediately because
				// the refused connection never reached a task.
				drop(permit);
				let refusal = crate::smtp::reply::Reply::single(
					421,
					"4.7.0 too many connections from your address",
				);
				let (mut read_half, mut write_half) = tokio::io::split(stream);
				// Drain the read side so the peer's bytes do not stall
				// the kernel buffer; the write side gets the refusal.
				tokio::spawn(async move {
					use tokio::io::{AsyncReadExt, AsyncWriteExt};
					let mut sink = [0u8; 1024];
					let _ = read_half.read(&mut sink).await;
					let _ = write_half.write_all(refusal.to_string().as_bytes()).await;
					let _ = write_half.shutdown().await;
				});
				continue;
			};
			let server = Arc::clone(&self);
			let tracked = self.drain.as_ref().map(crate::shutdown::Drain::track);
			let slot_for_task = Arc::clone(&per_ip);
			tokio::spawn(async move {
				let _permit = permit;
				let _tracked = tracked;
				let _slot = per_ip_slot;
				tracing::debug!(%peer, "connection accepted");
				if let Err(error) = server.handle(stream, Some(peer.ip())).await {
					tracing::debug!(%peer, %error, "connection ended with error");
				}
				// Releasing the slot explicitly is redundant (the
				// guard drops at scope end) but documents the contract
				// for future readers.
				drop(_slot);
				drop(slot_for_task);
			});
		}
	}

	/// Drive one connection from greeting to close. `peer` is the client
	/// address recorded in trace headers; `None` for in-memory tests.
	pub async fn handle<S>(&self, stream: S, peer: Option<IpAddr>) -> std::io::Result<()>
	where
		S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
	{
		match (self.tls_mode, &self.tls) {
			(TlsMode::Implicit, Some(acceptor)) => {
				let tls_stream = crate::tls::accept_within(&acceptor.current(), stream).await?;
				// A verified client certificate enables SASL EXTERNAL.
				let identity = tls_stream
					.get_ref()
					.1
					.peer_certificates()
					.and_then(|certs| certs.first())
					.and_then(|cert| crate::tls::identity_from_cert(cert.as_ref()));
				let mut session = self.new_session().with_tls_active();
				session.set_client_identity(identity);
				self.run(Box::new(tls_stream), session, peer).await
			}
			(TlsMode::Implicit, None) => Err(std::io::Error::other(
				"implicit TLS listener without TLS acceptor",
			)),
			(TlsMode::Opportunistic, Some(_)) => {
				let session = self.new_session().with_tls_available();
				self.run(Box::new(stream), session, peer).await
			}
			(TlsMode::Opportunistic, None) => {
				self.run(Box::new(stream), self.new_session(), peer).await
			}
		}
	}
}

async fn send<W>(writer: &mut W, reply: &Reply) -> std::io::Result<()>
where
	W: AsyncWrite + Unpin + ?Sized,
{
	writer.write_all(reply.to_string().as_bytes()).await?;
	writer.flush().await
}

/// Read exactly `size` bytes for a BDAT chunk (RFC 3030): first drain bytes
/// already buffered in the decoder, then read from the stream, feeding any
/// overshoot (the next pipelined command) back into the decoder. Returns
/// `Ok(None)` if the peer closes or times out before `size` bytes arrive.
async fn read_chunk(
	stream: &mut Box<dyn Connection>,
	decoder: &mut crate::smtp::line::LineDecoder,
	size: usize,
) -> std::io::Result<Option<Vec<u8>>> {
	use tokio::io::AsyncReadExt;
	let mut chunk = decoder.take_buffered(size);
	let mut buffer = [0u8; READ_BUFFER];
	while chunk.len() < size {
		let read = match tokio::time::timeout(COMMAND_TIMEOUT, stream.read(&mut buffer)).await {
			Ok(Ok(0)) | Err(_) => return Ok(None),
			Ok(Ok(n)) => n,
			Ok(Err(error)) => return Err(error),
		};
		let need = size - chunk.len();
		if read <= need {
			chunk.extend_from_slice(&buffer[..read]);
		} else {
			chunk.extend_from_slice(&buffer[..need]);
			decoder.feed(&buffer[need..read]);
		}
	}
	Ok(Some(chunk))
}

#[cfg(test)]
#[path = "server_tests_drain.rs"]
mod tests_drain;

#[cfg(test)]
#[path = "server_tests_quota.rs"]
mod tests_quota;

#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "server_tests_auth.rs"]
mod tests_auth;

#[cfg(test)]
#[path = "server_tests_bcc.rs"]
mod tests_bcc;

#[cfg(test)]
#[path = "server_tests_virus.rs"]
mod tests_virus;

#[cfg(test)]
#[path = "server_tests_trace.rs"]
mod tests_trace;

#[cfg(test)]
#[path = "server_tests_urlbl.rs"]
mod tests_urlbl;

#[cfg(test)]
#[path = "server_tests_save_sent.rs"]
mod tests_save_sent;

#[cfg(test)]
#[path = "server_tests_correspondents.rs"]
mod tests_correspondents;

#[cfg(test)]
#[path = "server_tests_subjectpass.rs"]
mod tests_subjectpass;

#[cfg(test)]
#[path = "server_tests_dual_stack.rs"]
mod tests_dual_stack;

#[cfg(test)]
#[path = "server_tests_starttls.rs"]
mod tests_starttls;

#[cfg(test)]
#[path = "server_tests_author.rs"]
mod tests_author;

#[cfg(test)]
#[path = "server_tests_sender_verified.rs"]
mod tests_sender_verified;
