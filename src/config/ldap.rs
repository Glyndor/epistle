//! LDAP / Active Directory directory backend configuration.
//!
//! When an `[ldap]` section is present the server authenticates logins that no
//! local or SQL account claims against the LDAP server (a live per-request
//! bind), and loads the LDAP user set into the in-memory directory for recipient
//! resolution. Every field is validated at load time; a malformed section aborts
//! startup (fail closed).

use serde::Deserialize;

/// The default attribute the account name is read from (POSIX `uid`).
fn default_account_attribute() -> String {
	"uid".to_string()
}

/// The default attribute the delivered addresses are read from.
fn default_mail_attribute() -> String {
	"mail".to_string()
}

/// The default resolution-load refresh interval, in seconds (one hour).
const fn default_refresh_secs() -> u64 {
	3600
}

/// LDAP/AD directory backend settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ldap {
	/// Server URL, `ldap://host:port` (plaintext or StartTLS) or `ldaps://...`
	/// (implicit TLS). Plaintext `ldap://` without `tls = true` sends the bind
	/// password in the clear — prefer `ldaps://` or StartTLS.
	pub url: String,
	/// DN of the service account used to search the directory.
	pub bind_dn: String,
	/// Password for the service account. Keep it out of the file with a `${VAR}`
	/// reference resolved from the environment at load time.
	pub bind_password: String,
	/// Base DN the user search starts from.
	pub base_dn: String,
	/// User search filter with a `%s` placeholder for the (escaped) login, e.g.
	/// `(uid=%s)` for OpenLDAP or `(sAMAccountName=%s)` for Active Directory.
	pub user_filter: String,
	/// Attribute the mapped account name is read from (default `uid`).
	#[serde(default = "default_account_attribute")]
	pub account_attribute: String,
	/// Attribute the delivered addresses are read from (default `mail`).
	#[serde(default = "default_mail_attribute")]
	pub mail_attribute: String,
	/// Seconds between resolution-load refreshes (default 3600).
	#[serde(default = "default_refresh_secs")]
	pub refresh_secs: u64,
	/// Request StartTLS on a plaintext `ldap://` URL. Ignored for `ldaps://`
	/// (already TLS). Off by default.
	#[serde(default)]
	pub tls: bool,
}

impl Ldap {
	/// Validate the section. Fails closed on a malformed configuration: a missing
	/// or wrongly-schemed URL, an empty required field, a filter without the `%s`
	/// placeholder, or a zero refresh interval.
	pub fn validate(&self) -> Result<(), String> {
		if !(self.url.starts_with("ldap://") || self.url.starts_with("ldaps://")) {
			return Err("ldap.url must start with ldap:// or ldaps://".to_string());
		}
		if self.bind_dn.is_empty() {
			return Err("ldap.bind_dn must not be empty".to_string());
		}
		if self.bind_password.is_empty() {
			return Err("ldap.bind_password must not be empty".to_string());
		}
		if self.base_dn.is_empty() {
			return Err("ldap.base_dn must not be empty".to_string());
		}
		if !self.user_filter.contains("%s") {
			return Err("ldap.user_filter must contain the %s login placeholder".to_string());
		}
		if self.account_attribute.is_empty() {
			return Err("ldap.account_attribute must not be empty".to_string());
		}
		if self.mail_attribute.is_empty() {
			return Err("ldap.mail_attribute must not be empty".to_string());
		}
		if self.refresh_secs == 0 {
			return Err("ldap.refresh_secs must be greater than zero".to_string());
		}
		Ok(())
	}
}

#[cfg(test)]
#[path = "ldap_tests.rs"]
mod tests;
