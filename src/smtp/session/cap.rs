//! Daily new-recipient cap (plan 4.10) applied at end-of-DATA on the
//! SMTP path. The cap is enforced after the oversize check and before
//! the message is handed to delivery, so a refused submission never
//! reaches the spool and leaves the per-account baseline untouched.
//!
//! The check is shared with `POST /api/v1/send` and JMAP
//! `EmailSubmission/set`; the three call sites use the same
//! `CorrespondentStore::enforce_new_recipient_cap` so the answers agree
//! bit-for-bit.

use std::sync::Arc;

use crate::api::log_send_limited;
use crate::smtp::session::AcceptedMessage;
use crate::storage::{CapOutcome, CorrespondentStore};

/// All cap-related state held by a session: the correspondent store,
/// the rolling 24h cap, and the listener's metrics handle. Kept in
/// one struct so the session can pass the whole thing around and the
/// caller does not have to thread three optional fields through every
/// helper.
#[derive(Debug)]
pub struct Cap {
	/// Per-account correspondent store; consulted at end-of-DATA to
	/// enforce the rolling 24h new-recipient cap. `None` disables the
	/// cap (the default) so tests that do not exercise it keep the
	/// pre-feature behaviour bit-for-bit.
	pub correspondents: Option<Arc<CorrespondentStore>>,
	/// Cap on first-time recipients per account in any rolling 24h
	/// window. `None` disables the cap. `correspondents` and this
	/// field are independent: a configured cap without a store
	/// short-circuits to "no cap" rather than failing closed.
	pub daily_new_recipients: Option<u32>,
	/// Shared metrics handle, bumped when a submission is refused for
	/// exceeding the cap. `None` is the listener-default.
	pub metrics: Option<Arc<crate::metrics::Metrics>>,
}

impl Cap {
	/// Empty cap state: every field `None`. Used by the session's
	/// `Default` initializer.
	pub fn empty() -> Self {
		Self {
			correspondents: None,
			daily_new_recipients: None,
			metrics: None,
		}
	}

	/// Attach the per-account correspondent store. Required for the
	/// cap to fire; absent here keeps the SMTP path on the pre-feature
	/// behaviour.
	pub fn with_correspondents(mut self, store: Arc<CorrespondentStore>) -> Self {
		self.correspondents = Some(store);
		self
	}

	/// Set the rolling 24h cap on first-time recipients per account.
	/// `None` disables the cap; the per-minute submission rate limit is
	/// unchanged either way.
	pub fn with_daily_new_recipients(mut self, limit: Option<u32>) -> Self {
		self.daily_new_recipients = limit;
		self
	}

	/// Share the listener's metrics handle so a refused submission can
	/// bump the `send_limited_new_recipients` counter. `None` (the
	/// default) is a no-op for the counter.
	pub fn with_metrics(mut self, metrics: Arc<crate::metrics::Metrics>) -> Self {
		self.metrics = Some(metrics);
		self
	}

	/// Whether the cap is enabled (both the store and the limit are
	/// configured). The end-of-DATA check uses this as a fast-path
	/// guard.
	pub fn enabled(&self) -> bool {
		self.correspondents.is_some() && self.daily_new_recipients.is_some()
	}
}

/// Outcome of [`enforce`], telling the caller what reply (if any) to
/// emit and whether to record the recipients before delivery.
pub enum Outcome {
	/// The cap is unset, the store is not wired in, the account is
	/// unknown, or the recipients fit inside the cap. The caller must
	/// record the recipients so a later submission sees them as known.
	Accept,
	/// The submission would exceed the cap. The caller must emit a
	/// `450 4.7.1 too many new recipients today; retry tomorrow` reply
	/// and **must not** record or deliver. The audit event and the
	/// metric counter are bumped before this returns.
	Limited,
}

/// Run the cap check against `account` (the authenticated account
/// name; `None` for an unauthenticated submission, which the SMTP path
/// skips entirely). The audit event carries the running total
/// (`new + already`).
pub fn enforce(
	account: Option<&str>,
	recipients: &[String],
	cap: &Cap,
	peer_ip: Option<std::net::IpAddr>,
) -> Outcome {
	let Some(account) = account else {
		return Outcome::Accept;
	};
	let (Some(store), Some(limit)) = (cap.correspondents.as_deref(), cap.daily_new_recipients)
	else {
		return Outcome::Accept;
	};
	let recipient_refs: Vec<&str> = recipients.iter().map(String::as_str).collect();
	match store.enforce_new_recipient_cap(account, &recipient_refs, Some(limit)) {
		Ok(CapOutcome::Limited {
			new,
			already,
			limit,
		}) => {
			if let Some(metrics) = cap.metrics.as_deref() {
				metrics.send_limited_new_recipients();
			}
			log_send_limited(account, peer_ip, new.saturating_add(already), limit);
			Outcome::Limited
		}
		Ok(CapOutcome::Allowed { .. } | CapOutcome::Uncapped) => Outcome::Accept,
		Err(error) => {
			tracing::warn!(account = %account, %error, "correspondent store error; accepting");
			Outcome::Accept
		}
	}
}

/// Record the recipients for `account` after the cap accepted the
/// submission. Best-effort: an I/O error is logged and swallowed.
pub fn record(account: &str, recipients: &[String], cap: &Cap) {
	let Some(store) = cap.correspondents.as_deref() else {
		return;
	};
	let recipient_refs: Vec<&str> = recipients.iter().map(String::as_str).collect();
	if let Err(error) = store.record(account, &recipient_refs) {
		tracing::warn!(account = %account, %error, "correspondent store error; not recording");
	}
}

/// Build the on-the-wire reply text for the SMTP path. Kept here so
/// the wording lives next to the check it backs.
pub fn limited_reply() -> crate::smtp::reply::Reply {
	crate::smtp::reply::Reply::single(450, "4.7.1 too many new recipients today; retry tomorrow")
}

/// Convenience for the SMTP run-loop: returns the reply to emit when
/// the submission must be refused (`Some`), or `None` when the
/// submission is accepted (the caller proceeds to deliver; recording
/// happens here as a side effect so a caller that forgets to record
/// still gets the right baseline).
pub fn check_or_reply(
	account: Option<&str>,
	message: &AcceptedMessage,
	cap: &Cap,
	peer_ip: Option<std::net::IpAddr>,
) -> Option<crate::smtp::reply::Reply> {
	match enforce(account, &message.recipients, cap, peer_ip) {
		Outcome::Limited => Some(limited_reply()),
		Outcome::Accept => {
			if let Some(account) = account {
				record(account, &message.recipients, cap);
			}
			None
		}
	}
}
