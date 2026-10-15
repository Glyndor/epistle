//! Which receiver group an exchanger belongs to.
//!
//! Large receivers judge a new sending address on their own, and they host
//! many domains behind the same exchangers: a Google Workspace domain is
//! received by Gmail, a Microsoft 365 domain by Outlook. The group is
//! therefore read from the exchanger host that answered, never from the
//! recipient domain.
//!
//! A host belongs to a provider only when one of the provider's names is a
//! whole-label suffix of it: `alt1.aspmx.l.google.com` is Gmail, while
//! `gmail-smtp-in.l.google.com.evil.example` and `evilgoogle.com` are not.
//! Anything else, an address literal included, is [`Group::Other`].

use serde::{Deserialize, Serialize};

/// A receiver group with its own warm-up schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Group {
	/// Gmail and Google Workspace.
	Gmail,
	/// Outlook.com, Hotmail and Microsoft 365.
	Outlook,
	/// Yahoo and AOL.
	Yahoo,
	/// iCloud Mail.
	Icloud,
	/// Every other receiver.
	Other,
}

/// The exchanger name suffixes of each named provider. Each one is matched
/// on whole labels.
const PROVIDERS: [(Group, &[&str]); 4] = [
	(Group::Gmail, &["google.com", "googlemail.com"]),
	(
		Group::Outlook,
		&["outlook.com", "hotmail.com", "mx.microsoft"],
	),
	(Group::Yahoo, &["yahoodns.net", "yahoo.com"]),
	(Group::Icloud, &["icloud.com"]),
];

impl Group {
	/// Every group, in the order reports list them.
	pub const ALL: [Group; 5] = [
		Group::Gmail,
		Group::Outlook,
		Group::Yahoo,
		Group::Icloud,
		Group::Other,
	];

	/// The group of the exchanger `host`, as normalised by
	/// [`crate::queue::destination::Destination`]: IDNA to ASCII, lower
	/// case, without the trailing dot.
	pub fn of_exchanger(host: &str) -> Group {
		let host = crate::queue::destination::Destination::exchanger(host);
		let host = host.as_str();
		PROVIDERS
			.iter()
			.find(|(_, suffixes)| suffixes.iter().any(|suffix| ends_with_labels(host, suffix)))
			.map_or(Group::Other, |(group, _)| *group)
	}

	/// The name used on the command line, in files and in events.
	pub fn label(self) -> &'static str {
		match self {
			Group::Gmail => "gmail",
			Group::Outlook => "outlook",
			Group::Yahoo => "yahoo",
			Group::Icloud => "icloud",
			Group::Other => "other",
		}
	}

	/// The group named `label`, or `None` for a name that is not one.
	pub fn parse(label: &str) -> Option<Group> {
		Group::ALL.into_iter().find(|group| group.label() == label)
	}

	/// Whether the provider itself answers for every host of the group,
	/// so that one refusal speaks for the whole group. Not so for
	/// [`Group::Other`], whose exchangers belong to whoever owns each
	/// recipient domain.
	pub fn is_provider(self) -> bool {
		self != Group::Other
	}
}

impl std::fmt::Display for Group {
	fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		out.write_str(self.label())
	}
}

/// Whether `suffix` is `host` or a run of whole labels at its end.
fn ends_with_labels(host: &str, suffix: &str) -> bool {
	match host.strip_suffix(suffix) {
		Some("") => true,
		Some(rest) => rest.ends_with('.'),
		None => false,
	}
}

#[cfg(test)]
#[path = "group_tests.rs"]
mod tests;
