//! SMTP network layer: accepts connections and drives sessions.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

pub use super::directory::Directory;
pub use super::diskspace::DiskGuard;
pub use super::memory_budget::MemoryBudget;
pub use super::ratelimit::SendLimiter;
pub use super::reply::Reply;
use super::session::Action;
pub use super::session::{AcceptedMessage, Session};
pub use super::sink::MessageSink;
pub use crate::directory_store::DirectoryHandle;
pub use data_rate::{DEFAULT_DATA_RATE_GRACE_SECS, DEFAULT_MIN_DATA_RATE, DataRate};
pub use session_time::{DEFAULT_MAX_SESSION_TIME_SECS, SessionLimits};

mod builder;
mod data_rate;
mod dnsbl_check;
mod run;
mod run_attachments;
mod run_auth;
mod run_band;
mod run_class;
mod run_sent;
mod session_time;

/// Read buffer size per connection.
const READ_BUFFER: usize = 4096;

/// Maximum concurrent connections per listener. Excess connections are dropped
/// immediately (TCP RST) to prevent file-descriptor exhaustion.
const MAX_CONNECTIONS: usize = 1000;

/// Maximum concurrent connections per client IP per listener. Excess
/// connections are answered `421 4.7.0 too many connections from your
/// address` and closed (RFC 5321 §4.5.3.2). The cap keeps a single
/// client from monopolising one listener; the per-listener connection
/// cap (1000 unless `max_connections_per_listener` says otherwise) still
/// bounds the total.
pub const DEFAULT_MAX_CONNECTIONS_PER_IP: usize = 20;
const MAX_CONNECTIONS_PER_IP: usize = DEFAULT_MAX_CONNECTIONS_PER_IP;

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
	/// The `[attachments]` policy for unauthenticated mail; `None` when off.
	attachments: Option<Arc<crate::antispam::attachments::policy::Policy>>,
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
	/// Default classes bound to accounts and credentials; `None` grants
	/// every submission `personal`.
	class_bindings: Option<Arc<crate::evidence::bindings::BindingSet>>,
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
	/// reach the other. A peer on a [`Server::with_trusted_networks`]
	/// CIDR is exempt; `serve` lists none, so in production no peer is.
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
	/// The minimum average rate of one DATA body or one BDAT chunk once
	/// its grace period is over (see [`DataRate`]).
	data_rate: DataRate,
	/// Commands without progress a session may send before it is closed;
	/// `0` turns the limit off.
	junk_command_limit: u32,
	/// How long one session may last before it is closed at the next
	/// command boundary; zero turns the limit off.
	max_session_time: Duration,
	/// The authentication protocol this listener serves. Sessions tag every
	/// password attempt through this server with it, so a per-account
	/// `allowed_protocols` set that does not include the listener's kind
	/// rejects the attempt identically to an unknown login. Default
	/// `Protocol::Submission` matches the historical behaviour (SMTP AUTH
	/// is client submission regardless of the listener's port).
	auth_protocol: crate::config::Protocol,
}

impl Server {
	/// Teach the shared Bayesian corpus from the server's own decisions, when
	/// a reputation/corpus database is configured: mail it rejects or
	/// quarantines is spam, mail it accepts is ham. The mail comes from
	/// anyone, so three rules keep one sender from deciding the corpus:
	/// ham is learned only from a sender the server verified (SPF or DKIM
	/// passed, `message.sender_verified`); each client address block, and
	/// each sender domain the server verified, has a bounded share of the
	/// learning for ham and for spam apart, and a job over it, or
	/// that the bounded queue cannot take, is dropped and counted in
	/// `mail_bayes_training_dropped_total`; and the job never waits, so the
	/// reply to the client does not depend on it. The no-op default on the
	/// trait keeps a fake scorer (test-only) cheap to wire in.
	fn train_corpus(
		&self,
		message: &crate::smtp::session::AcceptedMessage,
		peer: Option<IpAddr>,
		spam: bool,
	) {
		let Some(bayes) = &self.bayes else {
			return;
		};
		if !spam && !message.sender_verified {
			return;
		}
		// The envelope sender is whatever the client wrote. Its domain is a key
		// of the budget only once the server verified it; otherwise a client
		// could use up the budget of a domain it does not own.
		let domain = message
			.reverse_path
			.rsplit_once('@')
			.map(|(_, d)| d)
			.filter(|_| message.sender_verified);
		let source = crate::antispam::shared_training::TrainSource::new(peer, domain);
		if !bayes.train_from(&source, &message.data, spam) {
			self.metrics.bayes_training_dropped();
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
			.with_max_message_size(self.max_message_size)
			.with_junk_command_limit(self.junk_command_limit);
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
		let semaphore = Arc::new(crate::net::conn_limit::connection_semaphore(
			self.max_connections,
		));
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
				// the refused connection never reached a task. We do
				// not drain the read side: a peer that does not write
				// anything (the common case) would block the spawn
				// forever; the write of the 421 happens unconditionally.
				drop(permit);
				let refusal = crate::smtp::reply::Reply::single(
					421,
					"4.7.0 too many connections from your address",
				);
				let mut stream = stream;
				tokio::spawn(async move {
					use tokio::io::AsyncWriteExt;
					let _ = stream.write_all(refusal.to_string().as_bytes()).await;
					let _ = stream.flush().await;
					let _ = stream.shutdown().await;
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

/// Write one reply. A client that stops reading must not keep the
/// connection, nor whatever its session holds on the memory budget, in a
/// write that never ends: the write gives up after the same idle timeout
/// as a read.
async fn send<W>(writer: &mut W, reply: &Reply) -> std::io::Result<()>
where
	W: AsyncWrite + Unpin + ?Sized,
{
	let writing = async {
		writer.write_all(reply.to_string().as_bytes()).await?;
		writer.flush().await
	};
	tokio::time::timeout(COMMAND_TIMEOUT, writing)
		.await
		.unwrap_or_else(|_| {
			Err(std::io::Error::new(
				std::io::ErrorKind::TimedOut,
				"SMTP reply write timed out",
			))
		})
}

/// Read exactly `size` bytes for a BDAT chunk (RFC 3030) and hand them to
/// the session: first the bytes already buffered in the decoder, then the
/// stream, feeding any overshoot (the next pipelined command) back into the
/// decoder. Every read is charged to the memory budget before it is kept,
/// so the chunk holds only what has arrived; when the budget has no room
/// the transaction is refused, the rest of the chunk is read away through
/// [`discard_chunk`] and the client gets the 452. `window` is the rate
/// window of the whole transaction. Ends with a [`data_rate::Cut`] if the
/// peer closes or times out, or falls below the rate floor, before `size`
/// bytes arrive.
async fn read_chunk(
	stream: &mut Box<dyn Connection>,
	decoder: &mut crate::smtp::line::LineDecoder,
	chunk_of: (usize, bool),
	window: &mut data_rate::RateWindow,
	session: &mut Session,
) -> std::io::Result<Result<Action, data_rate::Cut>> {
	use tokio::io::AsyncReadExt;
	let (size, last) = chunk_of;
	let mut chunk = decoder.take_buffered(size);
	window.record(chunk.len());
	if !session.reserve_chunk(chunk.len()) {
		let left = size - chunk.len();
		drop(chunk);
		return refuse_chunk(stream, decoder, left, window, session).await;
	}
	let mut buffer = [0u8; READ_BUFFER];
	while chunk.len() < size {
		let reading = tokio::time::timeout(COMMAND_TIMEOUT, stream.read(&mut buffer));
		let read = match window.guard(reading).await {
			None => return Ok(Err(data_rate::Cut::TooSlow)),
			Some(Ok(Ok(0)) | Err(_)) => return Ok(Err(data_rate::Cut::Closed)),
			Some(Ok(Ok(n))) => n,
			Some(Ok(Err(error))) => return Err(error),
		};
		let need = size - chunk.len();
		let kept = read.min(need);
		window.record(kept);
		if read > need {
			decoder.feed(&buffer[need..read]);
		}
		if !session.reserve_chunk(kept) {
			// The octets just read are part of the chunk too.
			let left = size - chunk.len() - kept;
			drop(chunk);
			return refuse_chunk(stream, decoder, left, window, session).await;
		}
		chunk.extend_from_slice(&buffer[..kept]);
	}
	Ok(Ok(session.bdat_chunk(&chunk, last)))
}

/// A chunk the memory budget has no room for: the session drops the
/// transaction (and what it held) first, then the `left` octets still on
/// the wire are read away, so they are never parsed as commands.
async fn refuse_chunk(
	stream: &mut Box<dyn Connection>,
	decoder: &mut crate::smtp::line::LineDecoder,
	left: usize,
	window: &mut data_rate::RateWindow,
	session: &mut Session,
) -> std::io::Result<Result<Action, data_rate::Cut>> {
	let refusal = session.refuse_chunk();
	Ok(discard_chunk(stream, decoder, left, window)
		.await?
		.map(|()| refusal))
}

/// Read `size` bytes of a refused BDAT chunk and throw them away, without
/// holding them: first the bytes already buffered in the decoder, then the
/// stream through a fixed buffer, feeding any overshoot (the next pipelined
/// command) back into the decoder. The rate floor applies as to a kept
/// chunk: a dripped chunk still holds a connection and a per-IP slot.
async fn discard_chunk(
	stream: &mut Box<dyn Connection>,
	decoder: &mut crate::smtp::line::LineDecoder,
	size: usize,
	window: &mut data_rate::RateWindow,
) -> std::io::Result<Result<(), data_rate::Cut>> {
	use tokio::io::AsyncReadExt;
	let buffered = decoder.discard_buffered(size);
	window.record(buffered);
	let mut left = size - buffered;
	let mut buffer = [0u8; READ_BUFFER];
	while left > 0 {
		let reading = tokio::time::timeout(COMMAND_TIMEOUT, stream.read(&mut buffer));
		let read = match window.guard(reading).await {
			None => return Ok(Err(data_rate::Cut::TooSlow)),
			Some(Ok(Ok(0)) | Err(_)) => return Ok(Err(data_rate::Cut::Closed)),
			Some(Ok(Ok(n))) => n,
			Some(Ok(Err(error))) => return Err(error),
		};
		window.record(read.min(left));
		if read <= left {
			left -= read;
		} else {
			decoder.feed(&buffer[left..read]);
			left = 0;
		}
	}
	Ok(Ok(()))
}

/// End a connection whose read was cut: a client below the rate floor is
/// told why first. The session goes before the 421 is written, so a client
/// that does not read it gives its reservation back at the cut, not when
/// the write gives up.
async fn end_cut(
	stream: &mut Box<dyn Connection>,
	cut: data_rate::Cut,
	session: Session,
) -> std::io::Result<()> {
	drop(session);
	if cut == data_rate::Cut::TooSlow {
		tracing::info!("closing a client below the DATA/BDAT rate floor");
		send(stream, &data_rate::too_slow()).await?;
	}
	Ok(())
}

#[cfg(test)]
#[path = "tests_mods.rs"]
mod tests_mods;

#[cfg(test)]
#[path = "train_corpus_tests.rs"]
mod train_corpus_tests;
