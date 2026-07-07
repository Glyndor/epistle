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
		Ok(())
	}
}
