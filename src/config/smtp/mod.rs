//! The `[smtp]` section: what a refusal tells a sender that has not
//! authenticated.

use serde::Deserialize;

/// How much the text of a refusal tells a stranger. The enhanced status
/// code and the permanent or temporary class of a refusal are the same at
/// every level: only the words change.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RefusalDetail {
	/// The least a stranger can learn: the enhanced code and a generic
	/// sentence that names no check, list, policy or limit.
	Terse,
	/// What a refusal said before this setting existed.
	#[default]
	Standard,
	/// The actionable detail: what to fix for an SPF, DMARC or blocklist
	/// refusal, the figure of a limit and the time to retry at.
	Verbose,
}

/// The `[smtp]` section.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Smtp {
	/// How much a refusal sent to a sender that has not authenticated tells it.
	#[serde(default)]
	pub reject_detail: RefusalDetail,
	/// Whether a final refusal carries a short reference the sender can
	/// quote and the log line of the same refusal repeats.
	#[serde(default = "default_reference")]
	pub reject_reference: bool,
}

fn default_reference() -> bool {
	true
}

impl Default for Smtp {
	fn default() -> Self {
		Self {
			reject_detail: RefusalDetail::default(),
			reject_reference: default_reference(),
		}
	}
}

#[cfg(test)]
mod tests;
