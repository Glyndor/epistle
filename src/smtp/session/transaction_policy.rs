//! Per-session, per-MAIL-FROM policy state for [`Session`](super::Session).
//!
//! Two unrelated policies live here because both fit the same shape:
//! "an optional input set at construction, consulted once per MAIL FROM,
//! with a single helper that turns it into a pass/fail reply".
//!
//! - **Rate limits.** Per-account submission (authenticated sessions) plus
//!   per-IP and per-sender (unauthenticated). The helpers here carry the
//!   state and a one-call decision; the limiter type itself lives in
//!   [`super::ratelimit`].
//! - **Disk-space guard.** A single optional [`DiskGuard`](super::diskspace::DiskGuard)
//!   rejected with `452` when the spool cannot hold another message.
//!
//! Keeping them in one file keeps [`super::Session`] at a tractable size
//! without splitting by topic in a way that obscures the policy surface.

use std::net::IpAddr;
use std::sync::Arc;

use crate::smtp::directory::Directory;
use crate::smtp::diskspace::DiskGuard;
use crate::smtp::ratelimit::{InboundLimit, SendLimiter};
use crate::smtp::reply::Reply;

/// All MAIL-FROM-time policy state held by one session.
#[derive(Debug, Default)]
pub(crate) struct TransactionPolicy {
	/// Per-account submission limiter for authenticated senders. Set
	/// alongside `submission_default`.
	submission_limiter: Option<Arc<SendLimiter>>,
	/// Server-wide default submission cap (msgs/min). The per-domain
	/// entry on [`Directory::submission_limit_for`] wins; this is the
	/// fallback when no per-domain entry matches the account's domain.
	submission_default: Option<u32>,
	/// Per-client-IP inbound limiter and its per-minute cap, for
	/// unauthenticated sessions. Keyed by the peer `IpAddr`.
	inbound_ip: Option<InboundLimit>,
	/// Per-envelope-sender inbound limiter and its per-minute cap, for
	/// unauthenticated sessions. Keyed by the lowercased reverse path;
	/// the null sender (`<>`) used by bounces is always skipped.
	inbound_sender: Option<InboundLimit>,
	/// Shared disk-space guard for `data_dir`. When set, MAIL FROM is
	/// rejected with `452` if the filesystem cannot hold another message.
	disk_guard: Option<Arc<DiskGuard>>,
}

impl TransactionPolicy {
	// ---------- builders ----------

	/// Attach a shared per-account submission rate limiter.
	pub(crate) fn with_send_limiter(mut self, limiter: Arc<SendLimiter>) -> Self {
		self.submission_limiter = Some(limiter);
		self
	}

	/// Set the server-wide default submission rate limit (messages/min).
	/// The per-domain entry on the active directory wins at check time;
	/// this is the fallback used when no per-domain entry matches.
	pub(crate) fn with_global_submission_rate_limit(mut self, limit: Option<u32>) -> Self {
		self.submission_default = limit;
		self
	}

	/// Attach a shared per-client-IP inbound rate limiter and its
	/// per-minute cap. Consumed at `MAIL FROM` when the session never
	/// authenticated and a peer IP is known.
	pub(crate) fn with_inbound_ip_limit(mut self, limiter: Arc<SendLimiter>, per_min: u32) -> Self {
		self.inbound_ip = Some(InboundLimit { limiter, per_min });
		self
	}

	/// Attach a shared per-envelope-sender inbound rate limiter and its
	/// per-minute cap. Consumed at `MAIL FROM` when the session never
	/// authenticated and the reverse path is non-empty.
	pub(crate) fn with_inbound_sender_limit(
		mut self,
		limiter: Arc<SendLimiter>,
		per_min: u32,
	) -> Self {
		self.inbound_sender = Some(InboundLimit { limiter, per_min });
		self
	}

	/// Attach a shared disk-space guard for `data_dir`. When set, MAIL FROM
	/// is rejected with `452` if the filesystem cannot hold another
	/// message, so the remote retries instead of accepting a payload the
	/// spool cannot write.
	pub(crate) fn with_disk_guard(mut self, guard: Arc<DiskGuard>) -> Self {
		self.disk_guard = Some(guard);
		self
	}

	// ---------- checks ----------

	/// Whether a submission by the authenticated `account` is over the
	/// per-account submission limit (per-domain first, then the global
	/// default). Returns `true` when the session is allowed to send, or
	/// when no limit is configured; `false` only when a configured limit
	/// is exceeded.
	pub(crate) fn check_authenticated_submission(
		&self,
		account: &str,
		directory: &Directory,
		now: u64,
	) -> bool {
		let Some(limiter) = &self.submission_limiter else {
			return true;
		};
		let limit = directory
			.submission_limit_for(account)
			.or(self.submission_default);
		match limit {
			Some(per_min) => limiter.check(account, per_min, now),
			None => true,
		}
	}

	/// Whether an unauthenticated MAIL FROM with `reverse_path` from
	/// `peer_ip` is over either the per-IP or the per-sender inbound
	/// limit. Returns `Some(reply)` with the SMTP `450` reply to hand
	/// the remote, or `None` when nothing is configured, when no peer IP
	/// is known for the IP check, or when the reverse path is the null
	/// sender (`<>`) so the per-sender check is skipped.
	pub(crate) fn check_inbound(
		&self,
		reverse_path: &str,
		peer_ip: Option<IpAddr>,
		now: u64,
	) -> Option<Reply> {
		// Per-IP first: a peer flooding one address hits both limits,
		// but failing fast on the per-IP one keeps the per-sender budget
		// untouched for legitimate clients behind a shared NAT.
		if let (Some(ip_limit), Some(ip)) = (&self.inbound_ip, peer_ip)
			&& !ip_limit
				.limiter
				.check(&ip.to_string(), ip_limit.per_min, now)
		{
			return Some(Reply::single(
				450,
				"4.7.1 too many messages from this client; retry later",
			));
		}
		// Per-sender next, skipping the null reverse-path used by bounces
		// so a verification failure does not exhaust a legitimate sender.
		if let Some(sender_limit) = &self.inbound_sender
			&& !reverse_path.is_empty()
			&& !sender_limit.limiter.check(
				&reverse_path.to_ascii_lowercase(),
				sender_limit.per_min,
				now,
			) {
			return Some(Reply::single(
				450,
				"4.7.1 too many messages from this sender; retry later",
			));
		}
		None
	}

	/// Whether the spool still has room for a payload of `size_bytes`. When
	/// no guard is wired the check trivially passes.
	pub(crate) fn spool_has_room(&self, size_bytes: u64) -> bool {
		self.disk_guard
			.as_ref()
			.is_none_or(|guard| guard.has_room(size_bytes))
	}
}
