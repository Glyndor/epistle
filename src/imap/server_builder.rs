//! Builder methods that set the limits and options of the IMAP listener.

use super::*;

impl Server {
	/// Set APPENDLIMIT (RFC 7889), the largest literal an APPEND or
	/// REPLACE command may carry on this listener. `0` keeps the
	/// built-in default ([`crate::imap::command::DEFAULT_APPEND_LIMIT`]); any
	/// other value is taken as given. Flows from `[server]
	/// max_message_size`, the same cap the SMTP, REST and JMAP
	/// submission paths enforce.
	pub fn with_append_limit(mut self, bytes: usize) -> Self {
		if bytes > 0 {
			self.append_limit = bytes;
		}
		self
	}

	/// Apply the shared per-account counter after authentication. The
	/// listener must call this once at startup with the counter built
	/// from `[server] max_connections_per_account`. `None` keeps the
	/// listener free of any per-account cap (the historical behaviour).
	pub fn with_per_account_counter(
		mut self,
		counter: Arc<crate::net::per_account_conn::PerAccountCounter>,
	) -> Self {
		self.per_account_counter = Some(counter);
		self
	}

	/// Encrypt/decrypt stored message bodies at rest through `crypto`.
	pub fn with_crypto(mut self, crypto: crate::storage::MessageCrypto) -> Self {
		self.crypto = crypto;
		self
	}

	/// Days to keep expunged messages in `<account>/.archive/` before the
	/// hourly sweeper removes them. `0` keeps the legacy behaviour.
	pub fn with_retention_days(mut self, days: u64) -> Self {
		self.retention_days = days;
		self
	}

	/// Cap concurrent connections for this listener (0 keeps the default).
	pub fn with_max_connections(mut self, max: usize) -> Self {
		if max > 0 {
			self.max_connections = max;
		}
		self
	}

	/// Cap the connections one client may hold on this listener (0 keeps the
	/// default). An IPv6 client is counted by its /64.
	pub fn with_max_connections_per_ip(mut self, max: usize) -> Self {
		if max > 0 {
			self.max_per_ip = max;
		}
		self
	}

	/// Set the per-account storage quota applied to sessions.
	pub fn with_quota(mut self, bytes: u64) -> Self {
		self.quota_bytes = bytes;
		self
	}

	/// Accept OAUTHBEARER/XOAUTH2 bearer tokens, verified by `verifier`.
	pub fn with_oauth(mut self, verifier: Arc<crate::oauth::OauthVerifier>) -> Self {
		self.oauth = Some(verifier);
		self
	}

	/// Follow `drain`: stop accepting when it starts and close each
	/// session with `* BYE` once its current command is done.
	pub fn with_drain(mut self, drain: Arc<crate::shutdown::Drain>) -> Self {
		self.drain = Some(drain);
		self
	}

	/// Cap the idle / literal-read deadline. The default is 30 minutes
	/// (RFC 9051 §5.4); production callers leave it alone, but the test
	/// suite tightens it so a stalled APPEND/REPLACE literal does not stall
	/// a test for half an hour.
	pub fn with_read_timeout(mut self, timeout: Duration) -> Self {
		self.read_timeout = timeout;
		self
	}

	/// Set the deadline for the whole pre-authentication phase. The default
	/// is 60 seconds; a slow client or a slow password hash fits well within
	/// it, a client that holds the connection without signing in does not.
	pub fn with_preauth_timeout(mut self, timeout: Duration) -> Self {
		self.preauth_timeout = timeout;
		self
	}

	/// Provide the `tls-server-end-point` certificate hash, enabling
	/// AUTH=SCRAM-SHA-256-PLUS.
	pub fn with_channel_binding(mut self, cert_hash: crate::tls::EndPoint) -> Self {
		self.cbind_data = Some(cert_hash);
		self
	}

	/// Toggle the `[auth] scram` knob for this listener. `false` hides
	/// SCRAM-SHA-256 and SCRAM-SHA-256-PLUS in `CAPABILITY AUTH=` and
	/// refuses an explicit `AUTHENTICATE` against them; PLAIN/LOGIN stay in.
	pub fn with_scram_enabled(mut self, enabled: bool) -> Self {
		self.scram_enabled = enabled;
		self
	}

	/// Tag every password authentication attempt through this server with
	/// `protocol` so the directory's per-account `allowed_protocols` set
	/// can admit or reject it. Use the [`Protocol`](crate::config::Protocol) value matching the
	/// listener kind (`Protocol::Imaps` for implicit-TLS port 993,
	/// `Protocol::Imap` for the STARTTLS port 143).
	pub fn with_auth_protocol(mut self, protocol: crate::config::Protocol) -> Self {
		self.auth_protocol = protocol;
		self
	}

	/// Attach the training queue, shared with the JMAP state so both
	/// protocols feed the one worker of the process.
	pub fn with_training(mut self, queue: crate::antispam::training_queue::TrainingQueue) -> Self {
		self.training = Some(queue);
		self
	}
}
