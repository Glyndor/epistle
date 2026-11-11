//! Whether a JMAP call may set up something that sends mail on its own: a
//! Sieve script that redirects, replies or rejects, or a vacation reply that
//! is on. Two things can say no, and the refusal names which.

use super::Principal;
use crate::api::api_keys::Scope;
use crate::api::state::ApiState;

/// The answer for one account and one credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SendGate {
	/// The credential has the `send` scope and the account may send.
	Open,
	/// The credential lacks the `send` scope: `write` stores a filter, and
	/// does not originate mail.
	NoScope,
	/// The account's sending is switched off, so nothing it sets up could be
	/// sent. Delivery drops those messages, so the call says so up front.
	AccountOff,
}

impl SendGate {
	/// The gate for `account` as `principal` reaches it. A missing scope is
	/// reported before the account's own switch, since it is the one the
	/// caller can fix with another key.
	pub(super) fn of(state: &ApiState, principal: &Principal, account: &str) -> Self {
		if state
			.require_scope_for_principal(principal, Scope::Send)
			.is_err()
		{
			Self::NoScope
		} else if !state.can_send(account) {
			Self::AccountOff
		} else {
			Self::Open
		}
	}

	pub(super) fn is_open(self) -> bool {
		self == Self::Open
	}

	/// The SetError description for something that `what` names, refused by
	/// this gate.
	pub(super) fn describe(self, what: &str) -> String {
		match self {
			Self::AccountOff => {
				format!("{what} is not possible, sending is turned off for this account")
			}
			_ => format!("{what} needs the send scope"),
		}
	}
}
