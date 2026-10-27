//! Mail classes: what kind of mail a submission is, and what follows.
//!
//! - `transactional`: mail whose sending may have to be proved later (a
//!   notice, a receipt). Never copied to Sent, and an evidence record is
//!   always written before it is accepted.
//! - `marketing`: bulk mail. Refused without a one-click unsubscribe (RFC
//!   8058), sent with `Precedence: bulk`, never to a suppressed address.
//! - `personal`: everything else, and the default.
//!
//! The class is decided by the server. What is bound to the credential that
//! authenticated, else to the account, is a floor: an explicit field on the
//! API request may ask for a stricter class, never a looser one, so a key
//! made for notices cannot send mail that skips their evidence. The message
//! itself decides nothing: the [`CLASS_HEADER`] field is removed from every
//! submission and ignored.

use serde::{Deserialize, Serialize};

use crate::smtp::trace::{header_values, strip_headers_in_place};

/// The header field that used to let a client name a class. It is ignored
/// whatever it says, and always removed before the message is queued.
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
	/// How much the server asks of the sender: a stricter class is never
	/// replaced by a looser one that was merely requested.
	fn strictness(self) -> u8 {
		match self {
			Self::Personal => 0,
			Self::Marketing => 1,
			Self::Transactional => 2,
		}
	}

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
	/// The class the server grants, before the message is looked at: what is
	/// bound to the credential, else to the account, is the floor; an
	/// explicit field may only raise it.
	pub fn granted(&self) -> MailClass {
		let floor = self.credential.or(self.account);
		match (self.explicit, floor) {
			(Some(asked), Some(floor)) if asked.strictness() < floor.strictness() => floor,
			(Some(asked), _) => asked,
			(None, Some(floor)) => floor,
			(None, None) => MailClass::default(),
		}
	}
}

/// Decide the class of a submission and remove [`CLASS_HEADER`] from
/// `data`. The field changes nothing: the class is the one the server
/// grants, so a message can neither raise nor lower its own.
pub fn resolve(sources: ClassSources, data: &mut Vec<u8>) -> MailClass {
	if !header_values(data, CLASS_HEADER).is_empty() {
		strip_headers_in_place(data, &[CLASS_HEADER]);
	}
	sources.granted()
}

#[cfg(test)]
mod tests;
