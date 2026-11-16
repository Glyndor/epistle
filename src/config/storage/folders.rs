//! `[storage.folders]`: the names of an account's special folders and
//! whether the spam filters share one folder.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::config::ConfigError;

/// The folder an operator names for each role. A role left out keeps the
/// name of the level above it, and in the end the English default.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FolderNames {
	/// The spam folder, with the `\Junk` role.
	#[serde(default)]
	pub junk: Option<String>,
	/// The trash folder, with the `\Trash` role.
	#[serde(default)]
	pub trash: Option<String>,
	/// The folder for the copy of sent mail, with the `\Sent` role.
	#[serde(default)]
	pub sent: Option<String>,
	/// The drafts folder, with the `\Drafts` role.
	#[serde(default)]
	pub drafts: Option<String>,
	/// The archive folder, with the `\Archive` role.
	#[serde(default)]
	pub archive: Option<String>,
}

impl FolderNames {
	/// The name set for `role`, if any.
	pub fn get(&self, role: crate::imap::special_use::Role) -> Option<&str> {
		use crate::imap::special_use::Role;
		match role {
			Role::Junk => self.junk.as_deref(),
			Role::Trash => self.trash.as_deref(),
			Role::Sent => self.sent.as_deref(),
			Role::Drafts => self.drafts.as_deref(),
			Role::Archive => self.archive.as_deref(),
		}
	}

	/// This set with the roles it leaves out taken from `outer`.
	pub fn over(&self, outer: &FolderNames) -> FolderNames {
		FolderNames {
			junk: self.junk.clone().or_else(|| outer.junk.clone()),
			trash: self.trash.clone().or_else(|| outer.trash.clone()),
			sent: self.sent.clone().or_else(|| outer.sent.clone()),
			drafts: self.drafts.clone().or_else(|| outer.drafts.clone()),
			archive: self.archive.clone().or_else(|| outer.archive.clone()),
		}
	}

	fn validate(&self, place: &str) -> Result<(), ConfigError> {
		for role in crate::imap::special_use::Role::ALL {
			let Some(name) = self.get(role) else {
				continue;
			};
			let stored = crate::util::mutf7::encode(name);
			if !crate::util::mailbox_path::valid_folder(&stored) {
				return Err(ConfigError::Invalid(format!(
					"[storage.folders{place}] {} = {name:?} is not a valid folder name",
					role.key()
				)));
			}
		}
		Ok(())
	}
}

/// The `[storage.folders]` table.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Folders {
	/// One spam folder with the `\Junk` role for every filter (attachments,
	/// scanner hook, domain reputation, the LLM, Bayes and `rule.junk`).
	/// Default `false`: quarantined mail goes to `Rejects` and the Bayes
	/// verdict to `Junk`, both advertised as `\Junk`.
	#[serde(default)]
	pub single_spam_folder: bool,
	/// Names for every account of the server.
	#[serde(default)]
	pub names: FolderNames,
	/// Names for the accounts of one `[[tenant]]`, by its `name`.
	#[serde(default)]
	pub tenants: BTreeMap<String, FolderNames>,
	/// Names for the accounts of one domain. Beats the tenant's.
	#[serde(default)]
	pub domains: BTreeMap<String, FolderNames>,
}

impl Folders {
	/// Check every name and that each tenant and domain named is declared.
	pub(crate) fn validate(&self, config: &crate::config::Config) -> Result<(), ConfigError> {
		self.names.validate("")?;
		for (tenant, names) in &self.tenants {
			if !config
				.tenants
				.iter()
				.any(|declared| declared.name.as_deref() == Some(tenant.as_str()))
			{
				return Err(ConfigError::Invalid(format!(
					"[storage.folders.tenants.{tenant}] names a tenant that is not declared"
				)));
			}
			names.validate(&format!(".tenants.{tenant}"))?;
		}
		for (domain, names) in &self.domains {
			if !config
				.domains
				.iter()
				.any(|declared| declared.eq_ignore_ascii_case(domain))
			{
				return Err(ConfigError::Invalid(format!(
					"[storage.folders.domains.{domain}] names a domain the server does not host"
				)));
			}
			names.validate(&format!(".domains.{domain}"))?;
		}
		Ok(())
	}
}
