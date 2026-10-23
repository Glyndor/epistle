//! The copy of a message a mailing-list member receives, with the identity and
//! the cardinality of the `List-*` fields resolved by the last writer of that
//! copy.
//!
//! A submission from a list address already carries the block
//! [`crate::smtp::identification::apply`] writes, and local delivery used to
//! prepend the same block again, so a member got two `List-Id`, two
//! `List-Post` and two `List-Unsubscribe` from a message the client never
//! touched. This pass owns those fields on the copy instead of adding to them:
//! `List-Id` and `List-Post` say what the list is, so they are replaced, and
//! `List-Unsubscribe` is the list's own `mailto` only when the message carries
//! none. A one-click URL the sender published is therefore the one that stays,
//! the same policy the submission path applies (RFC 8058).

use crate::smtp::address::Address;
use crate::smtp::directory::Directory;
use crate::smtp::session::AcceptedMessage;
use crate::smtp::trace;

/// The copy a list member receives, or `None` when no recipient is a list and
/// the message is delivered as it is.
pub(super) fn list_copy(
	directory: &Directory,
	message: &AcceptedMessage,
) -> Option<AcceptedMessage> {
	let (address, identity) = message
		.recipients
		.iter()
		.filter_map(|recipient| Address::parse(recipient).ok())
		.find_map(|address| {
			let address = address.to_string();
			directory
				.list_identity(&address)
				.map(|identity| (address, identity))
		})?;
	let mut copy = message.clone();
	// What the list is, is the list's to say: whatever the message carried for
	// these two is replaced rather than repeated.
	trace::strip_headers_in_place(&mut copy.data, &["list-id", "list-post"]);
	let mut lines = identity;
	if trace::header_values(&copy.data, "list-unsubscribe").is_empty()
		&& let Some(unsubscribe) = directory.list_unsubscribe(&address)
	{
		lines.push_str(&unsubscribe);
		// RFC 8058 posts to an `https` URL and the `mailto` just written is
		// not one, so a post left behind names something the message does not
		// carry.
		trace::strip_headers_in_place(&mut copy.data, &["list-unsubscribe-post"]);
	}
	trace::prepend_header_block(&mut copy.data, &lines);
	Some(copy)
}
