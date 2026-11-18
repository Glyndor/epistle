//! Validation tests for accounts, addresses, ACME and DNS provider settings.

use super::base::config_from;
use super::*;

#[test]
fn rejects_account_with_unsafe_name() {
	for (name, expected) in [
		("", "must not be empty"),
		("Alice", "'A'"),
		("a/b", "'/'"),
		("-x", "hyphen"),
		("a b", "' '"),
		("torre.control", "'.'"),
		("josé", "'é'"),
	] {
		let result = config_from(&format!(
			"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\ndomains = [\"example.org\"]\n\n[[accounts]]\nname = \"{name}\"\naddresses = [\"a@example.org\"]\n"
		));
		assert!(
			matches!(&result, Err(ConfigError::Invalid(why)) if why.contains(expected)),
			"an invalid account name must be rejected naming {expected}"
		);
	}
}

#[test]
fn rejects_account_without_addresses() {
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[[accounts]]
name = "alice"
addresses = []
"#,
	);
	assert!(matches!(result, Err(ConfigError::Invalid(_))));
}

#[test]
fn rejects_address_outside_domains() {
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[[accounts]]
name = "alice"
addresses = ["alice@elsewhere.example"]
"#,
	);
	assert!(matches!(result, Err(ConfigError::Invalid(_))));
}

#[test]
fn rejects_address_claimed_twice() {
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[[accounts]]
name = "alice"
addresses = ["shared@example.org"]

[[accounts]]
name = "bob"
addresses = ["SHARED@example.org"]
"#,
	);
	assert!(matches!(result, Err(ConfigError::Invalid(_))));
}

#[test]
fn rejects_duplicate_account_names() {
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[[accounts]]
name = "alice"
addresses = ["a@example.org"]

[[accounts]]
name = "alice"
addresses = ["b@example.org"]
"#,
	);
	assert!(matches!(result, Err(ConfigError::Invalid(_))));
}

#[test]
fn accepts_same_port_on_different_addresses() {
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[[listeners]]
kind = "smtp"
addr = "127.0.0.1"

[[listeners]]
kind = "smtp"
addr = "127.0.0.2"
"#,
	);
	assert!(result.is_ok());
}

#[test]
fn accepts_acme_for_configured_domain() {
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[acme]
directory_url = "https://acme-v02.api.letsencrypt.org/directory"
domains = ["example.org"]
"#,
	);
	assert!(result.is_ok());
}

#[test]
fn rejects_acme_with_unconfigured_domain() {
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[acme]
directory_url = "https://acme.example/dir"
domains = ["other.example"]
"#,
	);
	assert!(matches!(result, Err(ConfigError::Invalid(_))));
}

#[test]
fn rejects_acme_with_non_https_directory() {
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[acme]
directory_url = "http://acme.example/dir"
domains = ["example.org"]
"#,
	);
	assert!(matches!(result, Err(ConfigError::Invalid(_))));
}

/// A `dns.provider` that is not in `SUPPORTED_PROVIDERS` must be
/// rejected at validate time with the list in the error message, so
/// the operator sees the typo before the server starts rather than
/// silently dropping into manual mode (the old behaviour, where
/// `Dns::build` returned `None` and nothing was published).
#[test]
fn rejects_unknown_dns_provider() {
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[dns]
provider = "cloudfare"
zone = "example.org"
token = "x"
"#,
	);
	let err = match result {
		Err(e) => e,
		Ok(_) => panic!("unknown provider must error"),
	};
	let rendered = format!("{err}");
	assert!(rendered.contains("cloudfare"), "{rendered}");
	assert!(rendered.contains("cloudflare"), "{rendered}");
	assert!(rendered.contains("manual"), "{rendered}");
}

/// The supported list is matched case-insensitively: `Cloudflare`
/// (capitalised) and `cloudflare` reach the same arm in `Dns::build`,
/// and the loader must accept both.
#[test]
fn accepts_capitalised_dns_provider() {
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[dns]
provider = "Cloudflare"
zone = "example.org"
token = "x"
"#,
	);
	assert!(result.is_ok(), "capitalised provider must validate");
}

/// `provider = "manual"` is in the supported list and must validate
/// even without any token, the provider is the always-available no-op.
#[test]
fn accepts_manual_dns_provider_without_credentials() {
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[dns]
provider = "manual"
zone = "example.org"
"#,
	);
	assert!(result.is_ok(), "manual provider must validate");
}
