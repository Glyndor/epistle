//! Validation of the identification header policy, whose only structured
//! value reaches a header of a message that leaves the server.

use super::{Config, ConfigError};

impl Config {
	/// The bulk threshold is a recipient count, so it cannot be zero: that
	/// would make every transactional submission with a recipient in it
	/// bulk, and a notice to one person is correspondence. An operator who
	/// wants no unsubscribe at all turns `default_list_unsubscribe` off,
	/// which says so in the configuration.
	pub(crate) fn validate_bulk_recipients(&self) -> Result<(), ConfigError> {
		if self.bulk_recipients == 0 {
			return Err(ConfigError::Invalid(
				"bulk_recipients (0) is below 1: it is a count of recipients, and \
				 zero would make every transactional submission bulk; turn \
				 default_list_unsubscribe = false for no unsubscribe at all"
					.to_string(),
			));
		}
		Ok(())
	}

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
