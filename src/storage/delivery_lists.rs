//! Which accounts a message reaches and which list each copy belongs to.
//!
//! The `List-*` headers (RFC 2369) identify the list a message was posted
//! to, so they belong to the delivery and not to the message: two lists in
//! one envelope keep their own identity, and a recipient addressed
//! directly takes none.

use std::collections::BTreeMap;

use crate::smtp::address::Address;
use crate::smtp::directory::Directory;
use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::SinkError;

/// The accounts a message reaches: each with the address its copy is
/// delivered as (the first one when several recipients reach the same
/// account) and the `List-*` headers of the list its delivery belongs to,
/// when that delivery went through one.
pub(super) type Recipients = BTreeMap<String, (String, Option<String>)>;

/// Resolve recipients to their distinct accounts. A multi-target alias fans
/// out to every member account, as the member's own address. The session
/// already rejected unresolvable recipients; hitting one here is a logic
/// error and fails the whole delivery (fail closed, client retries).
pub(super) fn accounts_for(
	directory: &Directory,
	message: &AcceptedMessage,
) -> Result<Recipients, SinkError> {
	let mut accounts: Recipients = BTreeMap::new();
	for recipient in &message.recipients {
		let address = Address::parse(recipient)
			.map_err(|_| SinkError::Unavailable(format!("unparseable recipient {recipient}")))?;
		let finals = directory.final_recipients(&address).ok_or_else(|| {
			SinkError::Unavailable(format!(
				"recipient {recipient} no longer resolves to an account"
			))
		})?;
		// The list identity belongs to the delivery, not to the message: a
		// recipient that reaches an account through a list carries that
		// list's headers, and a recipient addressed to the account itself
		// carries none.
		let list = directory.list_headers(&address.to_string());
		for (account, delivered_to) in finals {
			let slot = accounts
				.entry(account)
				.or_insert_with(|| (delivered_to, list.clone()));
			// A copy addressed to the account itself is not a list post, so
			// it keeps the plain message whatever else reached it.
			if slot.1.is_some() && list.is_none() {
				slot.1 = None;
			}
		}
	}
	Ok(accounts)
}

/// The message with a list's `List-*` headers prepended, for the copies
/// that belong to that list.
pub(super) fn listed_message(message: &AcceptedMessage, headers: &str) -> AcceptedMessage {
	let mut data = headers.as_bytes().to_vec();
	data.extend_from_slice(&message.data);
	AcceptedMessage {
		data,
		..message.clone()
	}
}
