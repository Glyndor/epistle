use super::*;

#[test]
fn parses_webhook_section() {
	let webhook: Webhook = toml::from_str(
		r#"
url = "https://hooks.example/mail"
secret = "s3cret"
"#,
	)
	.expect("parse webhook");
	assert_eq!(webhook.url, "https://hooks.example/mail");
	assert_eq!(webhook.secret.as_deref(), Some("s3cret"));
}

#[test]
fn a_webhook_is_on_unless_it_says_otherwise() {
	let on: Webhook = toml::from_str(r#"url = "https://hooks.example/mail""#).expect("parse");
	assert!(on.enabled);
	let off: Webhook = toml::from_str(
		r#"
url = "https://hooks.example/mail"
enabled = false
"#,
	)
	.expect("parse");
	assert!(!off.enabled);
}

#[test]
fn secret_is_optional_and_unknown_keys_rejected() {
	let webhook: Webhook = toml::from_str(r#"url = "https://hooks.example/mail""#).expect("parse");
	assert!(webhook.secret.is_none());
	assert!(toml::from_str::<Webhook>(r#"url = "x""#).is_ok());
	assert!(toml::from_str::<Webhook>(r#"nope = "x""#).is_err());
}
