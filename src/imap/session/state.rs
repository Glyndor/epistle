//! Session struct, state enum, and constructors.

use std::path::PathBuf;
use std::sync::Arc;

use crate::smtp::directory::Directory;

use super::super::command::NotifyEvent;
use super::auth::PendingAuth;
use super::mailbox::{Flag, Snapshot};

/// Server output produced by one step: complete response lines/literals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
	/// Raw bytes to write to the client. Includes any CRLF terminators.
	pub bytes: Vec<u8>,
	/// Whether the connection should be closed after sending `bytes`.
	pub close: bool,
	/// Size of a follow-on literal the client is expected to send (set by
	/// `APPEND`/`REPLACE`; `None` otherwise). When set, the network layer
	/// reads exactly that many bytes before invoking the session again.
	pub collect_literal: Option<usize>,
	/// Whether the session is now in the IDLE state; the network layer
	/// expects `DONE` or a 29-minute timeout before resuming the pump.
	pub idle: bool,
	/// Whether the connection should be upgraded to TLS (STARTTLS success).
	pub upgrade_tls: bool,
	/// Whether the connection should start deflating in both directions
	/// (COMPRESS=DEFLATE success). Set only after the tagged OK, which RFC
	/// 4978 §3 requires to travel uncompressed.
	pub compress: bool,
	/// Whether the session is in the middle of a SASL exchange and expects
	/// additional base64 challenge/response bytes from the client.
	pub collect_auth: bool,
}

impl Output {
	pub(super) fn text(text: String) -> Self {
		Output {
			bytes: text.into_bytes(),
			close: false,
			collect_literal: None,
			idle: false,
			upgrade_tls: false,
			compress: false,
			collect_auth: false,
		}
	}

	pub(super) fn closing(text: String) -> Self {
		Output {
			close: true,
			..Output::text(text)
		}
	}
}

/// A literal-bearing command (APPEND or REPLACE) awaiting its payload.
pub struct PendingLiteral {
	/// Tag stashed for the tagged completion response once the literal arrives.
	pub tag: String,
	/// Destination mailbox (REPLACE target).
	pub mailbox: String,
	/// Initial flags for the appended message.
	pub flags: Vec<Flag>,
	/// For REPLACE only: the selected mailbox to expunge from and the source
	/// message sequence number, resolved when the command was received.
	pub replace: Option<(String, u32)>,
}

/// State of one IMAP connection.
pub enum State {
	/// Pre-auth, tracking failed login attempts.
	NotAuthenticated {
		/// Consecutive failed login attempts; logout / close after three.
		login_failures: u8,
	},
	/// Authenticated but no mailbox selected.
	Authenticated {
		/// The local account name (`directory`-resolved).
		account: String,
	},
	/// A mailbox is currently selected.
	Selected {
		/// The local account name.
		account: String,
		/// The selected mailbox name.
		mailbox: String,
		/// Cached snapshot of the selected mailbox.
		snapshot: Snapshot,
		/// Whether the selection is read-only (from EXAMINE).
		read_only: bool,
	},
}

/// One IMAP connection's protocol state.
pub struct Session {
	pub(super) hostname: String,
	pub(super) data_dir: PathBuf,
	pub(super) directory: Arc<Directory>,
	pub(super) state: State,
	pub(super) pending_append: Option<PendingLiteral>,
	/// UIDONLY (RFC 9586) enabled: sequence-number commands are refused and
	/// responses use UID forms (UIDFETCH, VANISHED).
	pub(super) uidonly: bool,
	pub(super) idle_tag: Option<String>,
	/// NOTIFY (RFC 5465) events requested for the selected mailbox. `None` means
	/// NOTIFY is not active; an empty set means notifications are explicitly off.
	pub(super) notify_selected: Option<Vec<NotifyEvent>>,
	/// Whether the connection is inside TLS (LOGIN refused outside).
	pub(super) tls_active: bool,
	pub(super) tls_available: bool,
	pub(super) quota_limit_bytes: u64,
	pub(super) pending_auth: Option<PendingAuth>,
	pub(super) scram_nonce: Option<String>,
	pub(super) oauth: Option<Arc<crate::oauth::OauthVerifier>>,
	/// `tls-server-end-point` channel-binding data (server certificate hash)
	/// when known; enables AUTH=SCRAM-SHA-256-PLUS.
	pub(super) cbind_data: Option<Vec<u8>>,
	/// Verified TLS client-certificate identity (email SAN), enabling SASL
	/// EXTERNAL. Set by the network layer after a client-cert handshake.
	pub(super) client_identity: Option<String>,
	/// The client's peer IP, set by the network layer; used to enforce an app
	/// password's CIDR allowlist during authentication.
	pub(super) peer_ip: Option<std::net::IpAddr>,
	/// At-rest crypto for stored message bodies (read decode, append encode).
	pub(super) crypto: crate::storage::MessageCrypto,
	/// SEARCHRES (RFC 5182) saved set: the kind (`Seqnos`/`Uids`) plus the
	/// values themselves. Cleared on logout; replaced (not merged) by every
	/// successful `SEARCH ... RETURN (SAVE)`. Using `$` in a command whose
	/// UID-kind does not match the saved kind is rejected.
	pub(super) saved_search: Option<SavedSearch>,
	/// Days to keep expunged messages in `<account>/.archive/` before the
	/// hourly sweeper removes them. `0` keeps the legacy behaviour:
	/// expunge deletes the on-disk files immediately.
	retention_days: u64,
	/// Whether COMPRESS=DEFLATE is already active, so a second
	/// `COMPRESS` is refused rather than restarting the deflate context.
	pub(super) compressing: bool,
}

/// A SEARCHRES-saved result set (RFC 5182).
#[derive(Debug, Clone)]
pub struct SavedSearch {
	/// `true` if the saved values are UIDs (UID SEARCH); `false` for sequence
	/// numbers from a plain SEARCH.
	pub are_uids: bool,
	/// The matched identifiers (sequence numbers or UIDs).
	pub values: Vec<u32>,
}

/// Default per-account storage quota in bytes (5 GiB).
pub const DEFAULT_QUOTA_BYTES: u64 = 5 * 1024 * 1024 * 1024;

impl Session {
	/// Days to keep expunged messages in `<account>/.archive/` before the
	/// hourly sweeper removes them. `0` keeps the legacy behaviour.
	pub fn with_retention_days(mut self, days: u64) -> Self {
		self.retention_days = days;
		self
	}

	/// Open a mailbox snapshot with this session's retention and at-rest
	/// crypto, sampling the clock once so every expunge in a single command
	/// shares the same archive timestamp.
	///
	/// Every session path that can end in an expunge must open through here.
	/// `Snapshot::open` leaves `retention_days` at zero, so a call site that
	/// slips back to it deletes the mail the operator asked to keep, and
	/// nothing else would say so.
	pub(super) fn open_snapshot(
		&self,
		account: &str,
		mailbox: &str,
	) -> std::io::Result<super::mailbox::Snapshot> {
		let now = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.map(|d| d.as_secs())
			.unwrap_or(0);
		super::mailbox::Snapshot::open_at(
			&self.data_dir,
			account,
			mailbox,
			&self.crypto,
			self.retention_days,
			now,
		)
	}

	/// New session over an established TLS connection.
	pub fn new(hostname: &str, data_dir: PathBuf, directory: Arc<Directory>) -> Self {
		Session {
			hostname: hostname.to_string(),
			data_dir,
			directory,
			state: State::NotAuthenticated { login_failures: 0 },
			pending_append: None,
			uidonly: false,
			idle_tag: None,
			notify_selected: None,
			tls_active: true,
			tls_available: false,
			quota_limit_bytes: DEFAULT_QUOTA_BYTES,
			pending_auth: None,
			scram_nonce: None,
			oauth: None,
			cbind_data: None,
			client_identity: None,
			peer_ip: None,
			crypto: crate::storage::MessageCrypto::disabled(),
			retention_days: 0,
			compressing: false,
			saved_search: None,
		}
	}

	/// Use `crypto` to decode/encode stored message bodies at rest.
	pub fn with_crypto(mut self, crypto: crate::storage::MessageCrypto) -> Self {
		self.crypto = crypto;
		self
	}

	/// Set the verified TLS client-certificate identity (email), enabling SASL
	/// EXTERNAL for this connection.
	pub fn set_client_identity(&mut self, identity: Option<String>) {
		self.client_identity = identity;
	}

	/// Set the client's peer IP, used to enforce app-password CIDR allowlists.
	pub fn set_peer_ip(&mut self, ip: Option<std::net::IpAddr>) {
		self.peer_ip = ip;
	}

	/// Set the default storage quota (bytes) used when an account has no
	/// per-account or per-domain quota of its own.
	pub fn with_quota_limit(mut self, bytes: u64) -> Self {
		self.quota_limit_bytes = bytes;
		self
	}

	/// The storage quota in force for the authenticated account: its own /
	/// domain quota from the directory, else the server default.
	pub(super) fn effective_quota(&self) -> u64 {
		self.account()
			.and_then(|account| self.directory.quota_for(account))
			.unwrap_or(self.quota_limit_bytes)
	}

	/// Provide the `tls-server-end-point` channel-binding data (server
	/// certificate hash), enabling AUTH=SCRAM-SHA-256-PLUS.
	pub fn with_channel_binding(mut self, cert_hash: Vec<u8>) -> Self {
		self.cbind_data = Some(cert_hash);
		self
	}

	/// Mark this session as starting in plaintext with STARTTLS available.
	pub fn with_starttls(mut self) -> Self {
		self.tls_active = false;
		self.tls_available = true;
		self
	}

	/// Notify the session that the STARTTLS handshake completed: TLS is now
	/// active, STARTTLS is no longer available, and any pre-TLS login
	/// failures have been forgotten (a successful STARTTLS is a clean slate).
	pub fn tls_started(&mut self) {
		self.tls_active = true;
		self.tls_available = false;
		self.state = State::NotAuthenticated { login_failures: 0 };
	}
}
