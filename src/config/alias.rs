//! Multi-target alias definitions: one address fanning out to several accounts.

use serde::Deserialize;

/// An alias address delivering to multiple local accounts.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Alias {
	/// The alias address (e.g. `team@example.org`).
	pub address: String,
	/// Member addresses the alias delivers to (each a local account address).
	pub members: Vec<String>,
	/// Addresses permitted to send *as* this alias (From / MAIL FROM). Empty
	/// means any member may; a non-member is always refused.
	#[serde(default)]
	pub senders: Vec<String>,
	/// Keep the membership private: when true (the default) the member list is
	/// not disclosed through directory queries. Set false to make it visible.
	#[serde(default = "default_hidden")]
	pub hidden: bool,
	/// Treat this alias as a mailing list: when set, delivered copies carry
	/// `List-Id` (this value), `List-Post`, and `List-Unsubscribe` headers
	/// (RFC 2369/2919). Absent means a plain alias with no list headers.
	/// The value is written between the angle brackets the server adds, so it
	/// has to be an identifier those brackets can carry: a dot-atom of
	/// non-empty `atext` atoms joined by single dots. Anything else is
	/// refused at load.
	#[serde(default)]
	pub list_id: Option<String>,
}

/// Aliases hide their membership by default (privacy / secure by default).
fn default_hidden() -> bool {
	true
}

impl Alias {
	/// An alias must deliver somewhere.
	pub fn validate(&self) -> Result<(), String> {
		if self.members.is_empty() {
			return Err(format!("alias {} has no members", self.address));
		}
		// The table is loaded without running its addresses through the
		// address parser, so the Unicode line and paragraph separators the
		// parser refuses are refused here too.
		let separated = std::iter::once(&self.address)
			.chain(&self.members)
			.chain(&self.senders)
			.find(|address| crate::util::validation::has_line_separator(address));
		if let Some(address) = separated {
			return Err(format!(
				"alias {}: {address:?} carries a Unicode line or paragraph separator",
				self.address
			));
		}
		if let Some(list_id) = &self.list_id
			&& !usable_list_id(list_id)
		{
			return Err(format!(
				"alias {} has a list_id the list headers cannot carry",
				self.address
			));
		}
		Ok(())
	}
}

/// A `list_id` has to be an identifier the `List-Id` field can carry between
/// the angle brackets the server writes: RFC 2919 puts an identifier there, so
/// the value is read as a dot-atom, `atext` atoms joined by single dots.
///
/// A `>` would close those brackets early and leave the rest of the value
/// outside the identifier, a `<` would open a second pair inside them, a space
/// would split the identifier into two words, and a control character would end
/// the line and let the rest of the value read as further headers. A phrase
/// such as `Team List team.example.org` is none of those, but it is not an
/// identifier either: RFC 2919 spells a phrase as `Team List <id>`, with the
/// description outside the brackets, and this server does not compose one.
/// Neither case reaches a message: the configuration refuses the alias at load
/// and the composer refuses the value afterwards.
fn usable_list_id(list_id: &str) -> bool {
	let identifier = list_id.trim();
	!identifier.is_empty()
		&& identifier
			.split('.')
			.all(|atom| !atom.is_empty() && atom.chars().all(is_atext))
}

/// One character of an `atext` atom (RFC 5322 section 3.2.3): a letter, a
/// digit or one of the specials an address local part may carry.
fn is_atext(character: char) -> bool {
	character.is_ascii_alphanumeric() || crate::util::validation::ATEXT.contains(character)
}

#[cfg(test)]
#[path = "alias_separator_tests.rs"]
mod separator_tests;

#[cfg(test)]
#[path = "alias_tests.rs"]
mod tests;
