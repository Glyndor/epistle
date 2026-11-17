//! Which tenant a domain belongs to and which domain a domain alias
//! delivers to: the walk every per-scope setting shares, so the antispam
//! settings and the limits resolve a domain the same way.

use std::collections::HashMap;

use crate::config::Config;

/// `domain` as the scopes key it: lower case, no trailing dot.
pub(crate) fn key(domain: &str) -> String {
	domain.trim_end_matches('.').to_ascii_lowercase()
}

/// The domains of the configuration seen from the scopes.
#[derive(Clone, Debug, Default)]
pub(crate) struct Reach {
	/// Hosted domain to the name of the tenant that owns it.
	tenant_of: HashMap<String, String>,
	/// Domain alias to the domain it delivers to.
	domain_aliases: HashMap<String, String>,
}

impl Reach {
	/// The domains `config` declares.
	pub(crate) fn from_config(config: &Config) -> Self {
		let mut reach = Self {
			domain_aliases: config
				.domain_aliases
				.iter()
				.map(|(alias, target)| (key(alias), key(target)))
				.collect(),
			..Self::default()
		};
		for tenant in &config.tenants {
			if let Some(name) = &tenant.name {
				for domain in &tenant.domains {
					reach.tenant_of.insert(key(domain), name.clone());
				}
			}
		}
		reach
	}

	/// The hosted domain that mail for `domain` is delivered to, as keyed.
	pub(crate) fn hosted(&self, domain: &str) -> String {
		let domain = key(domain);
		self.domain_aliases.get(&domain).cloned().unwrap_or(domain)
	}

	/// The tenant that owns the already keyed hosted `domain`.
	pub(crate) fn tenant(&self, domain: &str) -> Option<&str> {
		self.tenant_of.get(domain).map(String::as_str)
	}
}
