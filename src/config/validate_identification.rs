//! Validation of the identification header policy, whose only structured
//! value reaches a header of a message that leaves the server.

use super::{Config, ConfigError};

impl Config {
	/// Every `domain_organization` key is a DNS name and every value is
	/// printable ASCII with no line break: the value is written into an
	/// `Organization` field of a message that leaves the server, so a
	/// control byte in the file would be a header injection the loader
	/// must not let through.
	pub(crate) fn validate_domain_organization(&self) -> Result<(), ConfigError> {
		let mut domains: Vec<&String> = self.domain_organization.keys().collect();
		domains.sort();
		for domain in domains {
			super::validate_dns_name("domain_organization key", domain)?;
			let value = &self.domain_organization[domain];
			if value.trim().is_empty() {
				return Err(ConfigError::Invalid(format!(
					"domain_organization[{domain}] must not be empty; remove the key instead"
				)));
			}
			if !value.is_ascii() || value.chars().any(char::is_control) {
				return Err(ConfigError::Invalid(format!(
					"domain_organization[{domain}] must be printable ASCII without control \
					 characters"
				)));
			}
		}
		Ok(())
	}
}
