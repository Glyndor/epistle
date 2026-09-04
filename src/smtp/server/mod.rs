//! SMTP network layer: accepts connections and drives sessions.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use super::directory::Directory;
use super::diskspace::DiskGuard;
use super::reply::Reply;
use super::session::Session;
use super::sink::MessageSink;
use crate::directory_store::DirectoryHandle;

mod dnsbl_check;
mod run;

/// Read buffer size per connection.
const READ_BUFFER: usize = 4096;

/// Maximum concurrent connections per listener. Excess connections are dropped
/// immediately (TCP RST) to prevent file-descriptor exhaustion.
const MAX_CONNECTIONS: usize = 1000;

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
	spf: Option<Arc<dyn crate::spf::DnsLookup>>,
	/// DNS blocklist zones to screen unauthenticated clients against.
	dnsbl: crate::dnsbl::Dnsbl,
	/// When set, accepted unauthenticated mail is recorded as ham.
	reputation: Option<sqlx::PgPool>,
	/// When set, the Bayesian corpus is trained on accept/reject decisions.
	bayes: Option<crate::antispam::corpus::BayesStore>,
	/// Optional external scanner hook consulted for unauthenticated mail.
	hook: Option<Arc<dyn crate::antispam::hook::MailHook>>,
	/// Optional LLM hook consulted for unauthenticated mail whose Bayesian
	/// score sits inside the configured uncertain band. Outside the band the
	/// classifier is not consulted at all, so a non-`None` value is cheap.
	llm: Option<crate::antispam::llm::LlmHook>,
	/// Shared metrics counters.
	metrics: Arc<crate::metrics::Metrics>,
	/// Delay applied to first-time unauthenticated senders. Zero disables it.
	first_time_delay: std::time::Duration,
	/// If set, DMARC delivery records are written here for aggregate reports.
	report_dir: Option<std::path::PathBuf>,
	/// If set, inbound unauthenticated mail is sealed into its ARC chain.
	arc_sealer: Option<Arc<crate::arc::sealer::ArcSealer>>,
	/// If set, greylist unseen triplets: the store and the delay in seconds.
	greylist: Option<(Arc<crate::antispam::greylist::MemoryGreylist>, u64)>,
	/// If set, OAUTHBEARER/XOAUTH2 tokens are accepted, verified by this.
	oauth: Option<Arc<crate::oauth::OauthVerifier>>,
	/// `tls-server-end-point` hash; enables SCRAM-SHA-256-PLUS on TLS sessions.
	cbind_data: Option<Vec<u8>>,
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
			spf: None,
			dnsbl: crate::dnsbl::Dnsbl::default(),
			reputation: None,
			bayes: None,
			hook: None,
			llm: None,
			metrics: Arc::new(crate::metrics::Metrics::new()),
			first_time_delay: std::time::Duration::ZERO,
			report_dir: None,
			arc_sealer: None,
			greylist: None,
			oauth: None,
			cbind_data: None,
			send_limiter: None,
			global_submission_rate_limit_per_min: None,
			inbound_ip_limit: None,
			inbound_sender_limit: None,
			tenant_limits: None,
			disk_guard: None,
			correspondents: None,
			daily_new_recipients: None,
			max_connections: MAX_CONNECTIONS,
			auth_protocol: crate::config::Protocol::Submission,
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

	/// Attach a shared disk-space guard for `data_dir`. The SMTP path
	/// consults it at `MAIL FROM` and rejects with `452` when the
	/// filesystem cannot hold another message, so the remote retries
	/// instead of receiving `250` for a payload the spool cannot write.
	pub fn with_disk_guard(mut self, guard: Arc<DiskGuard>) -> Self {
		self.disk_guard = Some(guard);
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

	/// Provide the `tls-server-end-point` certificate hash, enabling
	/// SCRAM-SHA-256-PLUS once a session is inside TLS.
	pub fn with_channel_binding(mut self, cert_hash: Vec<u8>) -> Self {
		self.cbind_data = Some(cert_hash);
		self
	}

	/// Accept OAUTHBEARER/XOAUTH2 bearer tokens, verified by `verifier`.
	pub fn with_oauth(mut self, verifier: Arc<crate::oauth::OauthVerifier>) -> Self {
		self.oauth = Some(verifier);
		self
	}

	/// Seal inbound unauthenticated mail into its ARC chain (RFC 8617).
	pub fn with_arc_sealer(mut self, sealer: Arc<crate::arc::sealer::ArcSealer>) -> Self {
		self.arc_sealer = Some(sealer);
		self
	}

	/// Greylist unseen triplets, deferring them for `delay_secs` seconds.
	pub fn with_greylist(
		mut self,
		store: Arc<crate::antispam::greylist::MemoryGreylist>,
		delay_secs: u64,
	) -> Self {
		self.greylist = Some((store, delay_secs));
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
	pub fn with_bayes(mut self, store: crate::antispam::corpus::BayesStore) -> Self {
		self.bayes = Some(store);
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
	/// own accept/reject decisions.
	fn train_corpus(&self, data: &[u8], spam: bool) {
		if let Some(bayes) = &self.bayes {
			let text = String::from_utf8_lossy(data).into_owned();
			bayes.train_in_background(crate::antispam::corpus::SHARED.to_string(), text, spam);
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
			.with_metrics(Arc::clone(&self.metrics));
		if let Some(verifier) = &self.oauth {
			session = session.with_oauth(Arc::clone(verifier));
		}
		if let Some(cbind) = &self.cbind_data {
			session = session.with_channel_binding(cbind.clone());
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
		let semaphore = Arc::new(Semaphore::new(self.max_connections));
		loop {
			let (stream, peer) = listener.accept().await?;
			let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() else {
				tracing::warn!(%peer, "SMTP connection limit reached, dropping");
				continue;
			};
			let server = Arc::clone(&self);
			tokio::spawn(async move {
				let _permit = permit;
				tracing::debug!(%peer, "connection accepted");
				if let Err(error) = server.handle(stream, Some(peer.ip())).await {
					tracing::debug!(%peer, %error, "connection ended with error");
				}
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
				let tls_stream = acceptor.current().accept(stream).await?;
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
#[path = "server_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "server_tests_auth.rs"]
mod tests_auth;

#[cfg(test)]
#[path = "server_tests_urlbl.rs"]
mod tests_urlbl;

#[cfg(test)]
#[path = "server_tests_correspondents.rs"]
mod tests_correspondents;
