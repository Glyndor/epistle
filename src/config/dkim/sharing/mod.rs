//! Which hosted domains share a DKIM key, read from the configuration alone.
//!
//! A domain that has no `[[dkim.domain]]` entry signs with the `[dkim]`
//! default key, so two such domains share one key. That is how installs
//! made before per-domain keys became the default work, and it is only
//! reported ([`Dkim::shared_default_warning`]). Two entries that name one
//! key file, or an entry that names a key file `[dkim]` also names, are a
//! configuration error: the operator wrote the sharing down, and a leaked
//! key would sign as every domain that uses it.
//!
//! The public keys inside the files are compared by
//! `crate::dkim::sharing`, which reads them; this module never opens a file.

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};

use super::Dkim;
use super::validate::hosted_set;
use crate::config::ConfigError;

/// How the default block is named when a message says it shares a key.
const DEFAULT_OWNER: &str = "[dkim] (the key every domain without its own key signs with)";

/// A path with `.` components and repeated separators removed, so
/// `/k/./a.pem` and `/k//a.pem` compare equal to `/k/a.pem`. No file is
/// read and no link is followed.
fn lexical(path: &Path) -> PathBuf {
	path.components()
		.filter(|component| !matches!(component, Component::CurDir))
		.collect()
}

impl Dkim {
	/// The hosted domains (lowercase, sorted) that sign with the `[dkim]`
	/// default key: every domain and domain alias without its own
	/// `[[dkim.domain]]` entry.
	pub fn domains_on_default(
		&self,
		domains: &[String],
		domain_aliases: &HashMap<String, String>,
	) -> Vec<String> {
		let mut sharing: Vec<String> = hosted_set(domains, domain_aliases)
			.into_iter()
			.filter(|domain| self.override_for(domain).is_none())
			.collect();
		sharing.sort();
		sharing
	}

	/// The advisory for an install whose `[dkim]` key signs more than one
	/// domain, `None` when each hosted domain has a key of its own.
	pub fn shared_default_warning(
		&self,
		domains: &[String],
		domain_aliases: &HashMap<String, String>,
	) -> Option<String> {
		let sharing = self.domains_on_default(domains, domain_aliases);
		if sharing.len() < 2 {
			return None;
		}
		Some(format!(
			"{} domains sign with the one [dkim] key ({}): a leaked key signs as every one of them. \
			 give each its own with `epistle dkim-keygen` and one [[dkim.domain]] entry",
			sharing.len(),
			sharing.join(", ")
		))
	}

	/// Refuse two entries, or an entry and `[dkim]`, that name one key file.
	pub(super) fn check_key_files_are_not_shared(&self) -> Result<(), ConfigError> {
		let mut owners: Vec<(PathBuf, String)> = std::iter::once(&self.key_file)
			.chain(self.rsa_key_file.as_ref())
			.map(|file| (lexical(file), DEFAULT_OWNER.to_string()))
			.collect();
		for entry in &self.domain {
			let owner = format!(
				"[dkim.domain] name = \"{}\"",
				entry.name.to_ascii_lowercase()
			);
			for file in std::iter::once(&entry.key_file).chain(entry.rsa_key_file.as_ref()) {
				let file = lexical(file);
				if let Some((_, other)) = owners.iter().find(|(known, _)| *known == file) {
					return Err(ConfigError::Invalid(format!(
						"{owner} and {other} use the same key file {}; \
						 every hosted domain needs a key of its own (`epistle dkim-keygen`)",
						file.display()
					)));
				}
				owners.push((file, owner.clone()));
			}
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests;
