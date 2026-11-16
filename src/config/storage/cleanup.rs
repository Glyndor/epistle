//! `[storage.cleanup]`: automatic removal of old mail from Trash, Junk,
//! Rejects and any folder by name.

use serde::Deserialize;

use crate::config::ConfigError;

/// Messages one hourly run removes at most, when the operator names none.
pub const DEFAULT_MAX_PER_RUN: u64 = 1000;

/// The longest retention a rule may name, in days (one hundred years).
pub const MAX_DAYS: u64 = 36_500;

fn default_max_per_run() -> u64 {
	DEFAULT_MAX_PER_RUN
}

/// Who a [`CleanupRule`] covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CleanupScope {
	/// Every account of the server.
	Server,
	/// The accounts of the `[[tenant]]` the rule's `name` names.
	Tenant,
	/// The accounts of the domain the rule's `name` names.
	Domain,
	/// The one account the rule's `name` names.
	Account,
}

/// One retention rule: `days` for `folder` in `scope`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CleanupRule {
	/// Who the rule covers. The narrower scope wins: account, then domain,
	/// then tenant, then server.
	pub scope: CleanupScope,
	/// The tenant, domain or account; absent for `server`.
	#[serde(default)]
	pub name: Option<String>,
	/// `trash`, `junk` or `rejects` for the folder with that role or name,
	/// or the name of any other folder.
	pub folder: String,
	/// Days a message stays in the folder before it is removed. `0` keeps it
	/// for ever, and beats a longer rule of a wider scope.
	pub days: u64,
}

/// The `[storage.cleanup]` table. Its presence turns the hourly cleanup on;
/// without it nothing is removed.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cleanup {
	/// Messages one hourly run removes at most, across every account. A run
	/// that hits the cap goes on from where it stopped at the next hour.
	/// Default 1000.
	#[serde(default = "default_max_per_run")]
	pub max_per_run: u64,
	/// The retention rules.
	#[serde(default, rename = "rule")]
	pub rules: Vec<CleanupRule>,
}

impl Default for Cleanup {
	fn default() -> Self {
		Cleanup {
			max_per_run: DEFAULT_MAX_PER_RUN,
			rules: Vec::new(),
		}
	}
}

/// Whether `folder` is one of the words that stand for a role.
pub fn is_selector_word(folder: &str) -> bool {
	["trash", "junk", "rejects"]
		.iter()
		.any(|word| folder.eq_ignore_ascii_case(word))
}

impl Cleanup {
	/// Check the cap and every rule.
	pub(crate) fn validate(&self, config: &crate::config::Config) -> Result<(), ConfigError> {
		let invalid = |text: String| Err(ConfigError::Invalid(format!("[storage.cleanup] {text}")));
		if self.max_per_run == 0 {
			return invalid("max_per_run must be at least 1".into());
		}
		for (at, rule) in self.rules.iter().enumerate() {
			let place = format!("rule {}", at + 1);
			if rule.days > MAX_DAYS {
				return invalid(format!("{place}: days must be at most {MAX_DAYS}"));
			}
			if !is_selector_word(&rule.folder)
				&& !crate::util::mailbox_path::valid_folder(&crate::util::mutf7::encode(
					&rule.folder,
				)) {
				return invalid(format!(
					"{place}: folder {:?} is not a folder name",
					rule.folder
				));
			}
			match (rule.scope, rule.name.as_deref()) {
				(CleanupScope::Server, None) => {}
				(CleanupScope::Server, Some(_)) => {
					return invalid(format!("{place}: a server rule has no name"));
				}
				(_, None) => return invalid(format!("{place}: the scope needs a name")),
				(CleanupScope::Tenant, Some(name)) => {
					if !config
						.tenants
						.iter()
						.any(|tenant| tenant.name.as_deref() == Some(name))
					{
						return invalid(format!("{place}: tenant {name:?} is not declared"));
					}
				}
				(CleanupScope::Domain, Some(name)) => {
					if !config
						.domains
						.iter()
						.any(|domain| domain.eq_ignore_ascii_case(name))
					{
						return invalid(format!("{place}: domain {name:?} is not hosted here"));
					}
				}
				(CleanupScope::Account, Some(name)) => {
					if crate::util::path_component::AccountName::new(name).is_err() {
						return invalid(format!("{place}: {name:?} is not an account name"));
					}
				}
			}
		}
		Ok(())
	}
}
