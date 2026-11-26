//! The daily cap on first-time recipients, as `POST /api/v1/send` and
//! `EmailSubmission/set` ask for it. SMTP asks the same store through
//! `smtp::session::cap`.
//!
//! With a cap configured the correspondent store is the check, so a message
//! it cannot check is refused, never accepted unchecked. Without one the store
//! only keeps the record of who an account wrote to, which a submission can do
//! without, and an error there is logged and the message goes on.

use super::state::ApiState;
use crate::storage::CapOutcome;

/// Why a submission was stopped at the cap.
pub(crate) enum CapRefusal {
	/// It would take the account over the cap.
	Limited,
	/// A cap is configured and could not be checked.
	Unavailable,
}

/// Check the cap for `account` and reserve `recipients` under it. Records the
/// recipients without a cap, so replies stay known. With `preview` the cap is
/// asked and nothing is reserved or recorded.
pub(crate) fn reserve(
	state: &ApiState,
	account: &str,
	recipients: &[String],
	preview: bool,
) -> Result<(), CapRefusal> {
	let capped = state.new_recipients_per_day().is_some();
	let Some(store) = state.correspondents() else {
		if capped {
			tracing::error!(
				account = %crate::log_id::account(account),
				"a new-recipient cap is configured and there is no correspondent store; refusing"
			);
			return Err(CapRefusal::Unavailable);
		}
		return Ok(());
	};
	let recipient_refs: Vec<&str> = recipients.iter().map(String::as_str).collect();
	let limit = state.new_recipients_per_day();
	let asked = if preview {
		store.preview_new_recipient_cap(account, &recipient_refs, limit)
	} else {
		store.enforce_new_recipient_cap(account, &recipient_refs, limit)
	};
	match asked {
		Ok(CapOutcome::Limited {
			new,
			already,
			limit,
		}) => {
			super::log_send_limited(account, None, new.saturating_add(already), limit);
			Err(CapRefusal::Limited)
		}
		Ok(CapOutcome::Allowed { .. } | CapOutcome::Uncapped) => Ok(()),
		Err(error) if capped => {
			tracing::error!(
				account = %crate::log_id::account(account),
				%error,
				"correspondent store error with a new-recipient cap configured; refusing"
			);
			Err(CapRefusal::Unavailable)
		}
		Err(error) => {
			tracing::warn!(
				account = %crate::log_id::account(account),
				%error,
				"correspondent store error; accepting"
			);
			Ok(())
		}
	}
}
