//! What the operator decided about the special folders of an account: the
//! name each role gets when the folder is created, and whether every spam
//! filter shares one folder.

use std::collections::BTreeMap;
use std::path::Path;

use super::{Role, Roles};
use crate::config::{Config, FolderNames};

/// The operator's folder policy, built once from `[storage.folders]`. The
/// default is today's behaviour: English names, and spam in `Rejects` (the
/// filters) and `Junk` (Bayes).
#[derive(Debug, Clone, Default)]
pub struct FolderPolicy {
	single_spam: bool,
	server: FolderNames,
	/// Per domain, the names of the domain over those of its tenant.
	domains: BTreeMap<String, FolderNames>,
}

impl FolderPolicy {
	/// The policy `config` asks for.
	pub fn from_config(config: &Config) -> FolderPolicy {
		let Some(folders) = config.storage.as_ref().map(|storage| &storage.folders) else {
			return FolderPolicy::default();
		};
		let mut domains: BTreeMap<String, FolderNames> = BTreeMap::new();
		for tenant in &config.tenants {
			let Some(names) = tenant
				.name
				.as_ref()
				.and_then(|name| folders.tenants.get(name))
			else {
				continue;
			};
			for domain in &tenant.domains {
				domains.insert(domain.to_ascii_lowercase(), names.clone());
			}
		}
		for (domain, names) in &folders.domains {
			let domain = domain.to_ascii_lowercase();
			let merged = match domains.get(&domain) {
				Some(tenant) => names.over(tenant),
				None => names.clone(),
			};
			domains.insert(domain, merged);
		}
		FolderPolicy {
			single_spam: folders.single_spam_folder,
			server: folders.names.clone(),
			domains,
		}
	}

	/// Whether every filter delivers spam to the one folder with the `\Junk`
	/// role.
	pub fn single_spam(&self) -> bool {
		self.single_spam
	}

	/// The name `role` gets when its folder is created for `account`: the
	/// domain's, else the tenant's, else the server's, else the default.
	pub fn name_for(&self, account: &str, role: Role) -> String {
		let domain = account
			.rsplit_once('@')
			.map(|(_, domain)| domain.to_ascii_lowercase());
		let operator = domain
			.as_ref()
			.and_then(|domain| self.domains.get(domain))
			.and_then(|names| names.get(role))
			.or_else(|| self.server.get(role));
		match operator {
			Some(name) => crate::util::mutf7::encode(name),
			None => self.default_name(role).to_string(),
		}
	}

	fn default_name(&self, role: Role) -> &'static str {
		match role {
			Role::Junk if self.single_spam => "Junk",
			Role::Junk => "Rejects",
			Role::Trash => "Trash",
			Role::Sent => "Sent",
			Role::Drafts => "Drafts",
			Role::Archive => "Archive",
		}
	}

	/// The mailbox a delivery to `logical` lands in for `account`. Only the
	/// names the spam filters use (`Rejects`, `Junk`) are redirected, and
	/// only when the account has a spam folder of its own choosing or the
	/// operator wants one spam folder; every other name is the caller's.
	pub fn delivery_target(&self, data_dir: &Path, account: &str, logical: &str) -> String {
		let filter_name =
			logical.eq_ignore_ascii_case("rejects") || logical.eq_ignore_ascii_case("junk");
		if !filter_name {
			return logical.to_string();
		}
		let roles = Roles::load(data_dir, account);
		if !self.single_spam && roles.recorded(Role::Junk).is_none() {
			return logical.to_string();
		}
		// Without the switch, a recorded folder that is gone leaves the filter
		// its own name, as it was before the role existed.
		let fallback = if self.single_spam {
			self.name_for(account, Role::Junk)
		} else {
			logical.to_string()
		};
		roles.folder(data_dir, account, Role::Junk, &fallback)
	}
}
