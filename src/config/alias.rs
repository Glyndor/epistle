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
	/// The value is written between angle brackets as it stands, so it may
	/// not carry a `>` or a control character; the alias is refused at load
	/// when it does.
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

/// A `list_id` has to survive the `List-Id` field it is written into: RFC 2919
/// puts the phrase between angle brackets the server writes, so a `>` closes
/// those brackets early and leaves the rest of the phrase outside the
/// identifier, and a control character ends the line and lets the rest of the
/// value read as further headers. Neither reaches a message: the configuration
/// refuses the alias at load and the composer refuses the value afterwards.
fn usable_list_id(list_id: &str) -> bool {
	!list_id.is_empty()
		&& list_id.is_ascii()
		&& !list_id.chars().any(|c| c.is_control() || c == '>')
}

#[cfg(test)]
#[path = "alias_separator_tests.rs"]
mod separator_tests;

#[cfg(test)]
#[path = "alias_tests.rs"]
mod tests;
