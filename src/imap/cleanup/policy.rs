//! Which retention applies to a folder: the operator's rules, the account's
//! preference, and how the two combine.

use std::collections::BTreeMap;

use crate::config::{CleanupScope, Config};
use crate::imap::special_use::{Role, Roles};

#[derive(Debug, Clone)]
struct Rule {
	scope: CleanupScope,
	/// Lower case; empty for the server.
	name: String,
	/// A [`rule_key`].
	folder: String,
	days: u64,
}

/// The operator's cleanup policy, built from `[storage.cleanup]`.
#[derive(Debug, Clone)]
pub struct Policy {
	max_per_run: u64,
	rules: Vec<Rule>,
	tenant_of_domain: BTreeMap<String, String>,
}

/// Whose mail a folder holds, for the scopes of the rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
	/// The account, lower case.
	pub account: String,
	/// The domain of the account.
	pub domain: Option<String>,
	/// The tenant of that domain.
	pub tenant: Option<String>,
}

impl Policy {
	/// The policy `config` asks for, or `None` when `[storage.cleanup]` is
	/// absent, which means nothing is removed.
	pub fn from_config(config: &Config) -> Option<Policy> {
		let cleanup = config.storage.as_ref()?.cleanup.as_ref()?;
		let rules = cleanup
			.rules
			.iter()
			.map(|rule| Rule {
				scope: rule.scope,
				name: rule.name.as_deref().unwrap_or("").to_ascii_lowercase(),
				folder: rule_key(&rule.folder),
				days: rule.days,
			})
			.collect();
		let mut tenant_of_domain = BTreeMap::new();
		for tenant in &config.tenants {
			if let Some(name) = &tenant.name {
				for domain in &tenant.domains {
					tenant_of_domain.insert(domain.to_ascii_lowercase(), name.to_ascii_lowercase());
				}
			}
		}
		Some(Policy {
			max_per_run: cleanup.max_per_run,
			rules,
			tenant_of_domain,
		})
	}

	/// The most messages one run removes.
	pub fn max_per_run(&self) -> usize {
		usize::try_from(self.max_per_run).unwrap_or(usize::MAX)
	}

	/// The scopes `account` falls under.
	pub fn subject(&self, account: &str) -> Subject {
		let account = account.to_ascii_lowercase();
		let domain = account
			.rsplit_once('@')
			.map(|(_, domain)| domain.to_string());
		let tenant = domain
			.as_ref()
			.and_then(|domain| self.tenant_of_domain.get(domain))
			.cloned();
		Subject {
			account,
			domain,
			tenant,
		}
	}

	/// The days the operator's rules give a folder with these `keys` (see
	/// [`folder_keys`]): the narrowest scope that has a rule for it, and in
	/// that scope the most specific key. `0` keeps for ever; `None` means no
	/// rule speaks for the folder.
	pub fn operator_days(&self, subject: &Subject, keys: &[String]) -> Option<u64> {
		resolve(
			self.rules.iter().map(|rule| {
				(
					rule.scope,
					rule.name.as_str(),
					rule.folder.as_str(),
					rule.days,
				)
			}),
			subject,
			keys,
		)
	}
}

/// How a rule names a folder, comparable with [`folder_keys`]: `word:trash`
/// for `trash`, `junk` and `rejects`, which name a role (or, for `rejects`, the
/// folder of that name), and `name:<stored name>` for any other folder. A
/// folder that is literally called `Trash` is not matched by `word:trash` once
/// the account gave the role to another folder. All lower case.
pub fn rule_key(folder: &str) -> String {
	if crate::config::cleanup_selector_word(folder) {
		stored_key(folder)
	} else {
		stored_key(&crate::util::mutf7::encode(folder))
	}
}

/// [`rule_key`] for a name that is already in its stored form.
pub(super) fn stored_key(folder: &str) -> String {
	let kind = if crate::config::cleanup_selector_word(folder) {
		"word"
	} else {
		"name"
	};
	format!("{kind}:{}", folder.to_ascii_lowercase())
}

/// The keys a rule can name a folder by, most specific first: its own name,
/// then `rejects` for the folder of that name, then `junk` or `trash` for a
/// folder that has the role.
pub fn folder_keys(name: &str, roles: &Roles) -> Vec<String> {
	let lower = name.to_ascii_lowercase();
	let mut keys = vec![format!("name:{lower}")];
	if lower == "rejects" {
		keys.push("word:rejects".into());
	}
	match roles.role_of(name) {
		Some(Role::Junk) => keys.push("word:junk".into()),
		Some(Role::Trash) => keys.push("word:trash".into()),
		_ => {}
	}
	keys
}

/// The days of the first rule that speaks for the folder: scopes from the
/// narrowest (`Account`) to the widest (`Server`), and in each scope the keys
/// in order. A rule is `(scope, name, folder, days)`.
pub fn resolve<'a>(
	rules: impl Iterator<Item = (CleanupScope, &'a str, &'a str, u64)> + Clone,
	subject: &Subject,
	keys: &[String],
) -> Option<u64> {
	let scopes = [
		(CleanupScope::Account, Some(subject.account.as_str())),
		(CleanupScope::Domain, subject.domain.as_deref()),
		(CleanupScope::Tenant, subject.tenant.as_deref()),
		(CleanupScope::Server, Some("")),
	];
	for (scope, name) in scopes {
		let Some(name) = name else {
			continue;
		};
		for key in keys {
			let hit = rules.clone().find(|(rule_scope, rule_name, folder, _)| {
				*rule_scope == scope && *rule_name == name && folder == key
			});
			if let Some((_, _, _, days)) = hit {
				return Some(days);
			}
		}
	}
	None
}

/// The retention that applies once the account's own preference is counted:
/// it may shorten the operator's, never lengthen it. An operator's `0` or no
/// operator rule at all sets no cap, so the account may set what it likes.
/// `0` is "keep for ever" and `None` is "nothing set".
pub fn combine(operator: Option<u64>, account: Option<u64>) -> Option<u64> {
	match (operator, account) {
		(operator, None) => operator,
		(None | Some(0), Some(days)) => Some(days),
		(Some(cap), Some(0)) => Some(cap),
		(Some(cap), Some(days)) => Some(cap.min(days)),
	}
}
