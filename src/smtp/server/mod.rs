//! SMTP network layer: accepts connections and drives sessions.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use super::directory::Directory;
use super::reply::Reply;
use super::session::Session;
use super::sink::MessageSink;
use crate::directory_store::DirectoryHandle;

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
	/// Optional external scanner hook consulted for unauthenticated mail.
	hook: Option<Arc<dyn crate::antispam::hook::MailHook>>,
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
			hook: None,
			metrics: Arc::new(crate::metrics::Metrics::new()),
			first_time_delay: std::time::Duration::ZERO,
			report_dir: None,
			arc_sealer: None,
			greylist: None,
			oauth: None,
		}
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

	/// Record sender reputation for accepted unauthenticated mail.
	pub fn with_reputation_pool(mut self, pool: sqlx::PgPool) -> Self {
		self.reputation = Some(pool);
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
		if let Some(pool) = &self.reputation {
			let text = String::from_utf8_lossy(data).into_owned();
			crate::antispam::corpus::train_in_background(pool.clone(), text, spam);
		}
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
		let session = Session::new(&self.hostname).with_directory(self.directory.current());
		match &self.oauth {
			Some(verifier) => session.with_oauth(Arc::clone(verifier)),
			None => session,
		}
	}

	/// Accept connections forever. Each connection runs in its own task.
	pub async fn serve(self: Arc<Self>, listener: TcpListener) -> std::io::Result<()> {
		let semaphore = Arc::new(Semaphore::new(MAX_CONNECTIONS));
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
				let session = self.new_session().with_tls_active();
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

#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;
