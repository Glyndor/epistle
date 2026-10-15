//! Mail classes: what kind of mail a submission is, and what follows.
//!
//! - `transactional`: mail whose sending may have to be proved later (a
//!   notice, a receipt). Never copied to Sent, and an evidence record is
//!   always written before it is accepted.
//! - `marketing`: bulk mail. Refused without a one-click unsubscribe (RFC
//!   8058), sent with `Precedence: bulk`, never to a suppressed address.
//! - `personal`: everything else, and the default.
//!
//! The class is decided by the server: an explicit field on the API request,
//! else the default bound to the credential that authenticated, else the
//! account default. A client may write the [`CLASS_HEADER`] field into the
//! message, but its only effect is a downgrade to `personal`: the field is
//! removed from every submission, so it never travels and never upgrades.

use serde::{Deserialize, Serialize};

use crate::smtp::trace::{header_values, strip_headers_in_place};

/// The header field a client may use to ask for `personal`. Any other value
/// is ignored, and the field is always removed before the message is queued.
pub const CLASS_HEADER: &str = "Epistle-Class";

/// The class of one submitted message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MailClass {
	/// Mail whose sending may have to be proved: evidence is mandatory.
	Transactional,
	/// Bulk mail: one-click unsubscribe required, suppressed addresses dropped.
	Marketing,
	/// Ordinary mail, the default.
	#[default]
	Personal,
}

impl MailClass {
	/// Every class, in a fixed order (for listings and policy tables).
	pub const ALL: [MailClass; 3] = [
		MailClass::Transactional,
		MailClass::Marketing,
		MailClass::Personal,
	];

	/// The wire and configuration name.
	pub fn as_str(self) -> &'static str {
		match self {
			Self::Transactional => "transactional",
			Self::Marketing => "marketing",
			Self::Personal => "personal",
		}
	}

	/// The class named `value` (exact, lowercase), or `None`. Unknown names
	/// fail closed at every boundary instead of falling back to a default.
	pub fn parse(value: &str) -> Option<Self> {
		match value {
			"transactional" => Some(Self::Transactional),
			"marketing" => Some(Self::Marketing),
			"personal" => Some(Self::Personal),
			_ => None,
		}
	}

	/// Whether a copy of this class may be stored in the sender's Sent
	/// folder. Transactional mail never is, whatever `save_sent` says.
	pub fn allows_sent_copy(self) -> bool {
		self != Self::Transactional
	}

	/// Whether an evidence record is mandatory, so that a failure to write
	/// it refuses the message.
	pub fn evidence_mandatory(self) -> bool {
		self == Self::Transactional
	}
}

/// Parse a class named on the command line.
pub fn parse_arg(value: &str) -> Result<MailClass, String> {
	MailClass::parse(value)
		.ok_or_else(|| format!("unknown class {value:?}: use transactional, marketing or personal"))
}

impl std::fmt::Display for MailClass {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		formatter.write_str(self.as_str())
	}
}

/// Where the server may take a class from, strongest first. None of these
/// is ever read from the message.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClassSources {
	/// The explicit field of the request (REST `class`, JMAP
	/// `epistle:class`).
	pub explicit: Option<MailClass>,
	/// The default bound to the credential that authenticated (an app
	/// password or an API key).
	pub credential: Option<MailClass>,
	/// The account default.
	pub account: Option<MailClass>,
}

impl ClassSources {
	/// The class the server grants, before the message is looked at.
	pub fn granted(&self) -> MailClass {
		self.explicit
			.or(self.credential)
			.or(self.account)
			.unwrap_or_default()
	}
}

/// Decide the class of a submission and remove [`CLASS_HEADER`] from
/// `data`. The result is the class the server grants, except that a field
/// asking for `personal` downgrades it; any other value of the field is
/// ignored, so the message can never raise its own class.
pub fn resolve(sources: ClassSources, data: &mut Vec<u8>) -> MailClass {
	let granted = sources.granted();
	let asked = header_values(data, CLASS_HEADER);
	if asked.is_empty() {
		return granted;
	}
	strip_headers_in_place(data, &[CLASS_HEADER]);
	let downgrade = asked
		.iter()
		.any(|value| value.eq_ignore_ascii_case(MailClass::Personal.as_str()));
	if downgrade {
		MailClass::Personal
	} else {
		granted
	}
}

#[cfg(test)]
#[path = "class_tests.rs"]
mod tests;
