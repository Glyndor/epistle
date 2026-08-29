//! Validation tests for the `[[tenant]]` block. Split out of `validate_tests.rs`
//! to stay under the line limit, matching the precedent set by the alert tests
//! in `validate_tests_c.rs`.

use super::tests::config_from;

#[test]
fn a_tenant_with_no_caps_loads() {
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["acme.example"]

[[tenant]]
domains = ["acme.example"]
"#,
	);
	assert!(result.is_ok(), "{:?}", result.err());
}

#[test]
fn a_tenant_must_reference_configured_domains() {
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["acme.example"]

[[tenant]]
name = "a"
domains = ["unknown.example"]
"#,
	);
	let message = result.expect_err("unknown domain").to_string();
	assert!(message.contains("unknown.example"), "{message}");
	assert!(message.contains("not a configured domain"), "{message}");
}

#[test]
fn duplicate_tenant_names_are_rejected() {
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["acme.example", "acme-mail.example"]

[[tenant]]
name = "a"
domains = ["acme.example"]

[[tenant]]
name = "a"
domains = ["acme-mail.example"]
"#,
	);
	let message = result.expect_err("duplicate tenant name").to_string();
	assert!(message.contains("more than once"), "{message}");
}

#[test]
fn two_tenants_claiming_the_same_domain_is_rejected_naming_both() {
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["shared.example"]

[[tenant]]
name = "a"
domains = ["shared.example"]

[[tenant]]
name = "b"
domains = ["shared.example"]
"#,
	);
	let message = result.expect_err("domain in two tenants").to_string();
	assert!(message.contains("\"a\""), "{message}");
	assert!(message.contains("\"b\""), "{message}");
	assert!(message.contains("shared.example"), "{message}");
}

#[test]
fn max_domains_smaller_than_declared_is_rejected() {
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["a.example", "b.example"]

[[tenant]]
name = "a"
domains = ["a.example", "b.example"]
max_domains = 1
"#,
	);
	let message = result.expect_err("max_domains too small").to_string();
	assert!(message.contains("max_domains"), "{message}");
}

#[test]
fn tenant_quota_smaller_than_sum_of_domain_quotas_is_rejected() {
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["a.example", "b.example"]

domain_quotas = { "a.example" = 100, "b.example" = 100 }

[[tenant]]
name = "tiny"
domains = ["a.example", "b.example"]
quota_bytes = 150
"#,
	);
	let message = result.expect_err("quota unreachable").to_string();
	assert!(message.contains("quota_bytes"), "{message}");
	assert!(message.contains("150"), "{message}");
	assert!(message.contains("200"), "{message}");
}

#[test]
fn tenant_quota_equal_to_sum_of_domain_quotas_loads() {
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["a.example", "b.example"]

domain_quotas = { "a.example" = 100, "b.example" = 100 }

[[tenant]]
name = "exact"
domains = ["a.example", "b.example"]
quota_bytes = 200
"#,
	);
	assert!(result.is_ok(), "{:?}", result.err());
}

#[test]
fn no_tenants_section_is_the_identity() {
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]
"#,
	);
	assert!(result.is_ok(), "{:?}", result.err());
}
