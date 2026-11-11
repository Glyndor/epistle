//! The registry of every secret and credential the server holds.
//!
//! One [`Entry`] per kind of secret says how it is rotated, how it is revoked
//! and what is left for the operator outside the server. The recovery
//! command reads this list and nothing else, so a kind that is not here is a
//! kind the procedure cannot name. A test (`src/cli/rotate/tests/coverage.rs`) fails the
//! build when the configuration gains a secret field no entry claims.

mod accounts;
mod keys;
mod outside;
mod storage;

/// Where the work of a rotation or a revocation happens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::cli) enum Handling {
	/// One `epistle` command does it on this server.
	Epistle(&'static str),
	/// The operator does it, by hand or at the provider; the text says how.
	Operator(&'static str),
	/// Epistle cannot do it yet; the issue tracks the work and `meanwhile`
	/// says what the operator can do today.
	Unsupported { issue: u32, meanwhile: &'static str },
}

impl Handling {
	/// Short name of the actor, for the summary and the JSON output.
	pub(in crate::cli) fn actor(&self) -> &'static str {
		match self {
			Handling::Epistle(_) => "epistle",
			Handling::Operator(_) => "operator",
			Handling::Unsupported { .. } => "unsupported",
		}
	}
}

/// One kind of secret or credential.
#[derive(Debug, Clone, Copy)]
pub(in crate::cli) struct Entry {
	/// Stable identifier, lowercase with dashes.
	pub id: &'static str,
	/// What it is, in a few words.
	pub name: &'static str,
	/// Where it lives.
	pub stored_in: &'static str,
	/// The configuration fields that hold it, as `Struct.field`. A field
	/// that names a file or an environment variable counts: it is the
	/// secret's handle. Empty for secrets kept outside `mail.toml`.
	pub config_fields: &'static [&'static str],
	pub rotate: Handling,
	pub revoke: Handling,
	/// What stays with the operator after the commands above, outside the
	/// server.
	pub operator_after: &'static [&'static str],
}

/// The issue that tracks the whole recovery procedure.
pub(in crate::cli) const TRACKING_ISSUE: u32 = 1497;

/// Link to an issue of the repository.
pub(in crate::cli) fn issue_url(number: u32) -> String {
	format!("https://github.com/Glyndor/epistle/issues/{number}")
}

/// Every entry, in the order the procedure walks them.
pub(in crate::cli) fn entries() -> impl Iterator<Item = &'static Entry> {
	[
		keys::ENTRIES,
		accounts::ENTRIES,
		storage::ENTRIES,
		outside::ENTRIES,
	]
	.into_iter()
	.flatten()
}
