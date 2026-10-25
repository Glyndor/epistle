//! The mailing-list fields of an alias with a `list_id`, composed rather than
//! interpolated. The address goes into each `mailto` percent-encoded per
//! RFC 6068, and every field goes through the composer, so a value that could
//! end the field early or start another one never reaches a message. The
//! encoder is the one the bulk `List-Unsubscribe` uses, so the list block and
//! the bulk block cannot disagree about how an address is spelled.

use super::Directory;
use crate::compose;
use crate::util::address::normalize;
use crate::util::mailto;

impl Directory {
	/// Mailing-list headers (`List-Id`/`List-Post`/`List-Unsubscribe`, each with
	/// a trailing CRLF) for an address, or `None` when it is not a list. Prepended
	/// to delivered copies so clients can identify and leave the list (RFC 2369).
	pub fn list_headers(&self, address: &str) -> Option<String> {
		let identity = self.list_identity(address)?;
		let unsubscribe = self.list_unsubscribe(address)?;
		Some(format!("{identity}{unsubscribe}"))
	}

	/// The `List-Id` and `List-Post` of a list address, each with a trailing
	/// CRLF, or `None` when it is not a list. The address is the canonical
	/// spelling of the alias, not the one the caller passed in. Kept apart
	/// from the `List-Unsubscribe` so a caller that already has one keeps it.
	///
	/// An identifier the `List-Id` cannot carry leaves the field out instead of
	/// going out as a phrase between the brackets. The configuration refuses
	/// such an alias at load; this is the same rule asked again where the block
	/// is composed, for a directory built in process rather than from a file.
	pub fn list_identity(&self, address: &str) -> Option<String> {
		let (address, list_id) = self.list_of(address)?;
		if !crate::config::usable_list_id(list_id) {
			return None;
		}
		let identity = field("List-Id", format!("<{list_id}>"))?;
		let post = field("List-Post", mailto::uri(&address))?;
		Some(identity + &post)
	}

	/// The `List-Unsubscribe` of a list address, a `mailto:` URI with the
	/// unsubscribe subject, or `None` when it is not a list. The address is
	/// the canonical spelling of the alias, not the one the caller passed in.
	pub fn list_unsubscribe(&self, address: &str) -> Option<String> {
		let (address, _) = self.list_of(address)?;
		field("List-Unsubscribe", mailto::unsubscribe(&address))
	}

	/// The canonical address of a list alias together with its `list_id`, or
	/// `None` for a plain alias.
	fn list_of(&self, address: &str) -> Option<(String, &str)> {
		let address = normalize(address);
		let list_id = self.aliases.get(&address)?.list_id.as_deref()?;
		Some((address, list_id))
	}
}

/// `Name: value` composed as a structured field, or `None` when the composer
/// refuses the value. A value it refuses is one that could end the field early
/// or is not ASCII, so the message goes out without the field and an operator
/// looking for the reason in the log finds it said, at most once an hour.
fn field(name: &str, value: String) -> Option<String> {
	compose::structured(name, &value)
		.map_err(|error| {
			if crate::util::warn_limited::allow(&format!("list-header:{name}")) {
				tracing::warn!(%name, %error, "list header left out of the message");
			}
		})
		.ok()
}
