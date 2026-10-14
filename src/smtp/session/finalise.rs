//! End-of-DATA finalisation shared by the dot-terminated and
//! CHUNKING (RFC 3030 BDAT) data paths. Both code paths produce an
//! `AcceptedMessage` and need the same post-DATA checks: the running
//! data size (already filtered by the data accumulation, so the check
//! is the authoritative oversize gate) and the rolling 24h
//! new-recipient cap (plan 4.10).
//!
//! The cap check fires only on the final action; intermediate BDAT
//! chunks return `Action::Continue(250)` directly from the network
//! layer. The check carries the audit/counter side effects and
//! records the recipients so a later submission sees them as known.

use super::types::{AcceptedMessage, State};
use super::{Action, Reply, Session, cap};
use crate::smtp::memory_budget::Reservation;

/// Build an `AcceptedMessage` from the in-flight `ReceivingData`
/// state, run the post-DATA checks, and emit the terminal `Action`.
/// Resets `session.state` to `Greeted` before returning so the next
/// command starts a fresh transaction. `running_size` is the
/// per-line data-size counter (which can exceed the per-instance cap
/// without truncating the body, because the accumulation path stops
/// extending past the ceiling; the original check used `*size`,
/// not `body.len()`).
pub fn finalise(session: &mut Session, message: AcceptedMessage, running_size: usize) -> Action {
	// The BDAT LAST path calls us with `session.state` still
	// `ReceivingData`; the DATA-dot path goes through
	// `finalise_from_state` which transitions first. Take the budget
	// fields out before the state goes, so the post-DATA checks see them.
	let (budget_exhausted, reserved) = match std::mem::replace(&mut session.state, State::Greeted) {
		State::ReceivingData {
			budget_exhausted,
			reserved,
			..
		} => (budget_exhausted, reserved),
		_ => (false, Reservation::none()),
	};
	inner_finalise(session, message, running_size, budget_exhausted, reserved)
}

/// The reply to a submission over one of its rate limits, at `MAIL FROM`
/// or at the end of DATA.
pub(super) fn rate_limited() -> Reply {
	let text = format!("4.7.1 {}", crate::smtp::submission_budget::RATE_LIMITED);
	Reply::single(450, &text)
}

/// Take out of `message` the local recipients it would put over quota.
/// `None` when that is every recipient: the message is refused whole. Else
/// the message goes on for the others and the sender gets one DSN for the
/// full mailboxes, sent by the server once the message is delivered
/// (SMTP has no per-recipient reply after DATA).
fn split_over_quota(
	session: &mut Session,
	mut message: AcceptedMessage,
	size: u64,
) -> Option<AcceptedMessage> {
	let Some(quota) = session.policy.quota() else {
		return Some(message);
	};
	let full = quota.overflowing(&session.directory, &message.recipients, size);
	if full.is_empty() {
		return Some(message);
	}
	if full.len() == message.recipients.len() {
		return None;
	}
	message
		.recipients
		.retain(|recipient| !full.contains(recipient));
	let notify: Vec<String> = full
		.into_iter()
		.filter(|recipient| !message.no_dsn.contains(recipient))
		.collect();
	if !notify.is_empty()
		&& let Some(report) = crate::queue::bounce::build(
			&session.hostname,
			&message.reverse_path,
			&notify,
			"552 5.2.2 mailbox full",
			&message.data,
			std::time::SystemTime::now(),
		) {
		session.policy.push_quota_report(report);
	}
	Some(message)
}

/// Convenience used by the dot-terminated path: build the message
/// from the in-flight state, then call [`finalise`]. The caller has
/// already matched `State::ReceivingData` for the borrow; this
/// helper moves the fields out by replacing the state with `Greeted`.
pub fn finalise_from_state(session: &mut Session) -> Action {
	let State::ReceivingData {
		reverse_path,
		recipients,
		no_dsn,
		size,
		body,
		require_tls,
		reserved,
		budget_exhausted,
		..
	} = std::mem::replace(&mut session.state, State::Greeted)
	else {
		return Action::Continue(Reply::bad_sequence());
	};
	let message = AcceptedMessage {
		reverse_path,
		recipients,
		no_dsn,
		data: body,
		require_tls,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: false,
	};
	inner_finalise(session, message, size, budget_exhausted, reserved)
}

/// The shared tail of [`finalise`]: the post-DATA checks. `reserved` is
/// the body's claim on the memory budget: a refusal drops it, which hands
/// the octets back, and an accepted body leaves it with the session so
/// the connection loop holds it until the delivery is over.
fn inner_finalise(
	session: &mut Session,
	message: AcceptedMessage,
	running_size: usize,
	budget_exhausted: bool,
	reserved: Reservation,
) -> Action {
	if budget_exhausted {
		return Action::Continue(Reply::single(
			452,
			"4.3.1 insufficient system resources; try again later",
		));
	}
	if running_size > session.max_message_size() {
		return Action::Continue(Reply::single(552, "5.3.4 message exceeds maximum size"));
	}
	if let Some(reply) = super::author::check(session, &message.data) {
		return Action::Continue(reply);
	}
	if let Some(reply) = cap::check_or_reply(
		session.authenticated.as_deref(),
		&message,
		&session.cap,
		session.peer_ip,
	) {
		return Action::Continue(reply);
	}
	// Submission rate limits, charged once per accepted message at one
	// unit per recipient (`RCPT TO` already refused the others), and only
	// after every check above passed. All limits or none: an over-limit
	// message costs nothing. A message refused whole for a full mailbox
	// gets its units back, and the server refunds the held charge when a
	// later check or the spool refuses the message.
	let charge = match session.authenticated.as_deref() {
		Some(account) => {
			let recipients = u32::try_from(message.recipients.len()).unwrap_or(u32::MAX);
			match session
				.policy
				.submission_budget(account, &session.directory)
				.charge(recipients, super::time::unix_now())
			{
				Ok(charge) => Some(charge),
				Err(_) => return Action::Continue(rate_limited()),
			}
		}
		None => None,
	};
	match split_over_quota(session, message, running_size as u64) {
		Some(message) => {
			session.policy.hold_charge(charge);
			session.delivery_reservation = reserved;
			Action::Deliver(Reply::ok(), message)
		}
		None => {
			if let Some(charge) = charge {
				charge.refund();
			}
			Action::Continue(Reply::single(552, "5.2.2 mailbox full"))
		}
	}
}
