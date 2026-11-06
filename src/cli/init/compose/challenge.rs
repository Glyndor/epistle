//! The challenge the configuration answers the ACME order with.
//!
//! Port 80 is where the certificate authority fetches the HTTP-01 token
//! (`/.well-known/acme-challenge/`). A configuration that answers with
//! `dns-01` or `tls-alpn-01` never has anything to say on it, and a
//! configuration with no `[acme]` section renews no certificate at all.
//! Publishing the port anyway is what made `podup` warn about it on
//! every `stack up`, and a warning that is always there is a warning
//! nobody reads: the one that mattered (#1588) went unnoticed behind
//! it.

use std::path::Path;

use crate::config::AcmeChallenge;

/// The `[acme]` section of a configuration, with the challenge it names.
#[derive(serde::Deserialize)]
struct Section {
	/// The challenge the certificate authority validates with. A section
	/// that leaves it out takes the default, which is HTTP-01.
	#[serde(default)]
	challenge: AcmeChallenge,
}

/// The challenge the configuration at `path` answers the ACME order
/// with, or `None` when the configuration carries no `[acme]` section.
///
/// A configuration that can not be read, or one that does not parse,
/// answers nothing, and says so the same way a configuration without an
/// `[acme]` section does: the caller then decides whether the section is
/// written at all.
pub(crate) fn in_config(path: &Path) -> Option<AcmeChallenge> {
	let text = crate::cli::regular::read::read_to_string(path).ok()?;
	let value: toml::Value = toml::from_str(&text).ok()?;
	let section = value.get("acme")?.as_table()?.clone();
	let section: Section = section.try_into().ok()?;
	Some(section.challenge)
}
