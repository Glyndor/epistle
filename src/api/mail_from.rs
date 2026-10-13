//! The send-as rule shared by `EmailSubmission/set` and `POST /api/v1/send`:
//! a non-empty envelope sender must be an address the acting account owns.

use super::state::ApiState;
use crate::smtp::address::Address;

/// Why an envelope sender was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MailFromRefusal {
	/// The sender does not parse as an address.
	Invalid,
	/// The acting account does not own the sender.
	NotOwned,
}

/// Check `mail_from` against `account`, the same way SMTP submission does
/// (`Directory::owns_address`). An empty sender is the null reverse path,
/// legal for bounces, and passes.
pub(crate) fn check_mail_from(
	state: &ApiState,
	account: &str,
	mail_from: &str,
) -> Result<(), MailFromRefusal> {
	if mail_from.is_empty() {
		return Ok(());
	}
	let parsed = Address::parse(mail_from).map_err(|_| MailFromRefusal::Invalid)?;
	if state.owns_address(account, &parsed) {
		Ok(())
	} else {
		Err(MailFromRefusal::NotOwned)
	}
}

/// Whether `account` may send `message` as its author: exactly one From
/// field naming exactly one address the account owns, the rule SMTP
/// submission applies at the end of DATA. The From header is what the
/// DKIM signature covers and what DMARC judges, so owning the envelope
/// sender alone is not enough.
pub(crate) fn owns_author(state: &ApiState, account: &str, message: &[u8]) -> bool {
	match crate::dmarc::author::author(message) {
		crate::dmarc::author::Author::Addresses(addresses) => match addresses.as_slice() {
			[address] => {
				Address::parse(address).is_ok_and(|parsed| state.owns_address(account, &parsed))
			}
			_ => false,
		},
		_ => false,
	}
}
