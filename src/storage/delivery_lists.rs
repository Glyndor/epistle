//! Which accounts a message reaches and which list each copy belongs to.
//!
//! The `List-*` headers (RFC 2369) identify the list a message was posted
//! to, so they belong to the delivery and not to the message: two lists in
//! one envelope keep their own identity, and a recipient addressed
//! directly takes none.
//!
//! An account gets one copy of a message. When it is a member of several
//! lists that the same envelope names, that copy carries the headers of the
//! first of them in the order of the envelope recipients, and none of the
//! others; when it is also addressed directly, the direct address wins
//! whichever comes first, and the copy is the message as it came.

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
		// carries none. The account keeps the first one it reaches: an
		// existing slot is never given a second list.
		let list = directory.list_headers(&address.to_string());
		for (account, delivered_to) in finals {
			let slot = accounts
				.entry(account)
				.or_insert_with(|| (delivered_to, list.clone()));
			// A copy addressed to the account itself is not a list post, so
			// it keeps the plain message whatever else reached it, before
			// or after the list in the envelope.
			if slot.1.is_some() && list.is_none() {
				slot.1 = None;
			}
		}
	}
	Ok(accounts)
}

/// The copies of a message that carry a list's `List-*` headers, built once
/// per distinct list however many members the list has. A copy is the
/// headers followed by the body, so building one per member would copy the
/// whole message once for each of them.
pub(super) struct ListedCopies<'a> {
	message: &'a AcceptedMessage,
	built: BTreeMap<String, AcceptedMessage>,
	/// How many copies were built, for the test that pins one per list.
	#[cfg(test)]
	builds: usize,
}

impl<'a> ListedCopies<'a> {
	pub(super) fn new(message: &'a AcceptedMessage) -> Self {
		Self {
			message,
			built: BTreeMap::new(),
			#[cfg(test)]
			builds: 0,
		}
	}

	/// The message a recipient's copy is made from: the message as it came
	/// when the delivery did not go through a list, and otherwise the
	/// message with that list's headers prepended.
	pub(super) fn for_list(&mut self, headers: Option<&str>) -> &AcceptedMessage {
		let Some(headers) = headers else {
			return self.message;
		};
		if !self.built.contains_key(headers) {
			#[cfg(test)]
			{
				self.builds += 1;
			}
			self.built
				.insert(headers.to_string(), listed_message(self.message, headers));
		}
		&self.built[headers]
	}
}

/// The message with a list's `List-*` headers prepended. Every field is
/// named so that a field added to [`AcceptedMessage`] fails to compile here
/// instead of being dropped, and the body is copied once, into the result.
fn listed_message(message: &AcceptedMessage, headers: &str) -> AcceptedMessage {
	let mut data = Vec::with_capacity(headers.len() + message.data.len());
	data.extend_from_slice(headers.as_bytes());
	data.extend_from_slice(&message.data);
	AcceptedMessage {
		reverse_path: message.reverse_path.clone(),
		recipients: message.recipients.clone(),
		data,
		require_tls: message.require_tls,
		mailbox: message.mailbox.clone(),
		tlsrpt_verified: message.tlsrpt_verified,
		sender_verified: message.sender_verified,
		no_dsn: message.no_dsn.clone(),
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn message() -> AcceptedMessage {
		AcceptedMessage {
			reverse_path: "sender@elsewhere.example".into(),
			recipients: vec!["team@example.org".into()],
			data: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
			require_tls: true,
			mailbox: Some("Lists".into()),
			tlsrpt_verified: false,
			sender_verified: true,
			no_dsn: vec!["bob@example.org".into()],
		}
	}

	/// Every member of one list is handed the same built copy, so a list of a
	/// thousand members copies the body once and not a thousand times; a
	/// second list gets its own, and a delivery through no list gets the
	/// message itself.
	#[test]
	fn a_list_is_built_once_however_many_members_it_has() {
		let message = message();
		let mut copies = ListedCopies::new(&message);
		for _ in 0..3 {
			copies.for_list(Some("List-Id: <a>\r\n"));
		}
		assert_eq!(copies.builds, 1, "the same list must reuse its copy");
		let other = copies.for_list(Some("List-Id: <b>\r\n"));
		assert!(other.data.starts_with(b"List-Id: <b>\r\n"));
		assert_eq!(copies.builds, 2, "a second list gets its own copy");
		let plain = copies.for_list(None);
		assert!(
			std::ptr::eq(plain, &message),
			"no list: the message as it came"
		);
	}

	/// The listed copy is the message with the headers in front and nothing
	/// else changed.
	#[test]
	fn a_listed_copy_keeps_every_other_field() {
		let message = message();
		let copy = listed_message(&message, "List-Id: <a>\r\n");
		assert_eq!(copy.data, b"List-Id: <a>\r\nSubject: hi\r\n\r\nbody\r\n");
		assert_eq!(copy.reverse_path, message.reverse_path);
		assert_eq!(copy.recipients, message.recipients);
		assert_eq!(copy.mailbox, message.mailbox);
		assert_eq!(copy.no_dsn, message.no_dsn);
		assert!(copy.require_tls && copy.sender_verified && !copy.tlsrpt_verified);
	}
}
