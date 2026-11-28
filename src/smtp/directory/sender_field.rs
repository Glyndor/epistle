//! The send-as rule for the `Sender` fields of a submitted message, one
//! implementation for SMTP submission and JMAP `EmailSubmission/set`.
//! `POST /api/v1/send` takes the one address it writes in the field as a
//! request value and holds it to the same ownership rule.

use crate::dmarc::author::{all_sender_addresses, sender_unreadable};
use crate::smtp::address::Address;

/// Why the `Sender` fields of a message were refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SenderRefusal {
	/// A field names no address, or the header block cannot be read.
	Unreadable,
	/// An address does not parse.
	Invalid,
	/// The account may not send as an address.
	NotOwned,
}

/// Every address of every `Sender` field of `message`, in the lowercase form
/// the envelope holds, once `owns` accepted each of them. A message without
/// the field gives an empty list. Every field and every address of each is
/// held to the rule, and the first one that fails is reported.
pub(crate) fn owned_sender_addresses(
	message: &[u8],
	owns: impl Fn(&Address) -> bool,
) -> Result<Vec<String>, SenderRefusal> {
	if sender_unreadable(message) {
		return Err(SenderRefusal::Unreadable);
	}
	let addresses = all_sender_addresses(message);
	for address in &addresses {
		let parsed = Address::parse(address).map_err(|_| SenderRefusal::Invalid)?;
		if !owns(&parsed) {
			return Err(SenderRefusal::NotOwned);
		}
	}
	Ok(addresses)
}
