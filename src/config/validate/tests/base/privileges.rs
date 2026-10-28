//! Tests for `[privileges]` validation.

use super::config_from;
use crate::config::ConfigError;

#[test]
fn accepts_privileges_section() {
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[privileges]
user = "glyndor-epistle"
group = "glyndor-epistle"
"#,
	);
	assert!(result.is_ok());
}

#[test]
fn rejects_empty_privileges_user() {
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[privileges]
user = "  "
"#,
	);
	assert!(matches!(result, Err(ConfigError::Invalid(_))));
}

#[test]
fn rejects_empty_privileges_group() {
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[privileges]
user = "glyndor-epistle"
group = ""
"#,
	);
	assert!(matches!(result, Err(ConfigError::Invalid(_))));
}
