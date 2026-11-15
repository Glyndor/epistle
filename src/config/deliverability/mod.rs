//! `[deliverability]`: the sender panels the operator has enrolled in.
//!
//! Every big provider has a portal where the sender watches what the
//! provider thinks of the sending addresses: the spam rate, the complaints,
//! the standing of the sending IP. Enrolling in one is a step in a provider's
//! own web page, and epistle only records that the operator did it.
//!
//! The list names the portals that are done. `epistle check deliverability`
//! reminds about the ones that are missing and only warns: the list changes
//! no behaviour of the server.
//!
//! The steps of each enrolment, what the portal shows and the limits the
//! provider asks the sender to stay inside are in
//! `docs/operations/providers.md`.

use serde::{Deserialize, Deserializer};

/// A sender panel the operator can enrol in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Portal {
	/// Google Postmaster Tools: the spam rate of the domain and the
	/// reputation Gmail gives it.
	Postmaster,
	/// Microsoft SNDS: the health of the sending IP addresses and their
	/// standing with Outlook.com.
	Snds,
	/// Microsoft JMRP: the complaint reports, inside SNDS.
	Jmrp,
	/// Yahoo Complaint Feedback Loop: the complaints of the DKIM-signed mail
	/// of an enrolled domain.
	YahooCfl,
	/// The Apple iCloud Mail postmaster contact: the address that asks
	/// Apple to look at a sending address.
	Apple,
}

impl Portal {
	/// Every portal, in the order the reference lists them.
	pub const ALL: [Portal; 5] = [
		Portal::Postmaster,
		Portal::Snds,
		Portal::Jmrp,
		Portal::YahooCfl,
		Portal::Apple,
	];

	/// The name the configuration writes.
	pub const fn name(self) -> &'static str {
		match self {
			Portal::Postmaster => "postmaster",
			Portal::Snds => "snds",
			Portal::Jmrp => "jmrp",
			Portal::YahooCfl => "yahoo-cfl",
			Portal::Apple => "apple",
		}
	}

	/// The portal a name names, `None` when it names none.
	pub fn parse(name: &str) -> Option<Portal> {
		Portal::ALL.into_iter().find(|portal| portal.name() == name)
	}

	/// The names of every portal, for the error that names them.
	pub fn names() -> Vec<&'static str> {
		Portal::ALL
			.into_iter()
			.map(|portal| portal.name())
			.collect()
	}

	/// What the portal is, in one line, for the operator.
	pub const fn what(self) -> &'static str {
		match self {
			Portal::Postmaster => "Google Postmaster Tools",
			Portal::Snds => "Microsoft SNDS",
			Portal::Jmrp => "Microsoft JMRP",
			Portal::YahooCfl => "Yahoo Complaint Feedback Loop",
			Portal::Apple => "the Apple iCloud Mail postmaster contact",
		}
	}

	/// Where the portal lives.
	pub const fn page(self) -> &'static str {
		match self {
			Portal::Postmaster => "https://support.google.com/mail/answer/9981691",
			Portal::Snds | Portal::Jmrp => {
				"https://substrate.office.com/ip-domain-management-snds/snds"
			}
			Portal::YahooCfl => "https://senders.yahooinc.com/complaint-feedback-loop/",
			Portal::Apple => "https://support.apple.com/en-us/102322",
		}
	}
}

/// Read a portal from the configuration. An unknown name is refused the way
/// an unknown key is: the error names the portals that exist.
impl<'de> Deserialize<'de> for Portal {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		struct PortalVisitor;

		impl serde::de::Visitor<'_> for PortalVisitor {
			type Value = Portal;

			fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
				write!(
					formatter,
					"one of the sender panels: {}",
					Portal::names().join(", ")
				)
			}

			fn visit_str<E>(self, value: &str) -> Result<Portal, E>
			where
				E: serde::de::Error,
			{
				Portal::parse(value).ok_or_else(|| {
					E::custom(format!(
						"unknown [deliverability] enrolled panel {value:?}; the panels are: {}",
						Portal::names().join(", ")
					))
				})
			}
		}

		deserializer.deserialize_str(PortalVisitor)
	}
}

/// The `[deliverability]` section.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Deliverability {
	/// The panels the operator has enrolled in. Empty by default: every
	/// panel is then reported as missing.
	#[serde(default)]
	pub enrolled: Vec<Portal>,
}

impl Deliverability {
	/// Whether `portal` is in the list.
	pub fn has(&self, portal: Portal) -> bool {
		self.enrolled.contains(&portal)
	}

	/// The panels that are not in the list, in the order of [`Portal::ALL`].
	pub fn missing(&self) -> Vec<Portal> {
		Portal::ALL
			.into_iter()
			.filter(|portal| !self.has(*portal))
			.collect()
	}
}
