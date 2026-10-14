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
use crate::smtp::submission_budget::{Budget, Charge};

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
	/// Per-tenant aggregate submission limits. `None` (the default)
	/// short-circuits every tenant check to the pre-tenancy identity.
	tenant_limits: Option<Arc<crate::api::TenantLimits>>,
	/// Shared disk-space guard for `data_dir`. When set, MAIL FROM is
	/// rejected with `452` if the filesystem cannot hold another message.
	disk_guard: Option<Arc<DiskGuard>>,
	/// Mailbox quota of local recipients: `RCPT TO` refuses a full mailbox,
	/// and the end of DATA catches one this message would overfill.
	quota: Option<Arc<crate::smtp::quota::MailboxQuota>>,
	/// Failure reports (DSNs) for recipients the last accepted message
	/// could not be stored for, waiting for the server to send them once
	/// the message itself is delivered.
	quota_reports: Vec<super::types::AcceptedMessage>,
	/// The submission-limit charge of the last message handed to the
	/// server, kept only once the server accepts it.
	pending_charge: Option<Charge>,
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

	/// Attach the shared per-tenant submission limits, charged together
	/// with the per-account limit through [`Self::submission_budget`].
	pub(crate) fn with_tenant_limits(mut self, limits: Arc<crate::api::TenantLimits>) -> Self {
		self.tenant_limits = Some(limits);
		self
	}

	// ---------- checks ----------

	/// The submission limits of the authenticated `account`: its domain's
	/// per-account limit (else the server-wide default) and every tenant
	/// owning one of its addresses. Empty when none is configured.
	pub(crate) fn submission_budget(&self, account: &str, directory: &Directory) -> Budget {
		let account_limit = self.submission_limiter.as_ref().and_then(|limiter| {
			directory
				.submission_limit_for(account)
				.or(self.submission_default)
				.map(|per_min| (limiter, per_min))
		});
		Budget::for_account(
			account,
			account_limit,
			self.tenant_limits.as_deref(),
			|| directory.addresses_for(account),
		)
	}

	/// Hold the charge of a message handed to the server for delivery.
	pub(crate) fn hold_charge(&mut self, charge: Option<Charge>) {
		self.pending_charge = charge;
	}

	/// The charge of the message just handed to the server, if any.
	pub(crate) fn take_charge(&mut self) -> Option<Charge> {
		self.pending_charge.take()
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

	/// Check local recipients against their mailbox quota.
	pub(crate) fn with_quota(mut self, quota: Arc<crate::smtp::quota::MailboxQuota>) -> Self {
		self.quota = Some(quota);
		self
	}

	/// The mailbox quota checks, when wired.
	pub(crate) fn quota(&self) -> Option<&crate::smtp::quota::MailboxQuota> {
		self.quota.as_deref()
	}

	/// Queue a failure report to send after the message is delivered.
	pub(crate) fn push_quota_report(&mut self, report: super::types::AcceptedMessage) {
		self.quota_reports.push(report);
	}

	/// Take the failure reports waiting to be sent.
	pub(crate) fn take_quota_reports(&mut self) -> Vec<super::types::AcceptedMessage> {
		std::mem::take(&mut self.quota_reports)
	}

	/// Whether the spool still has room for a payload of `size_bytes`. When
	/// no guard is wired the check trivially passes.
	pub(crate) fn spool_has_room(&self, size_bytes: u64) -> bool {
		self.disk_guard
			.as_ref()
			.is_none_or(|guard| guard.has_room(size_bytes))
	}
}
