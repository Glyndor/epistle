	use super::*;

	#[test]
	fn parses_tenant_block() {
		let tenant: Tenant = toml::from_str(
			r#"
name = "acme"
domains = ["acme.example", "acme-mail.example"]
quota_bytes = 1073741824
max_accounts = 50
max_domains = 5
submission_rate_limit_per_min = 200
"#,
		)
		.expect("parse tenant");
		assert_eq!(tenant.name.as_deref(), Some("acme"));
		assert_eq!(tenant.domains.len(), 2);
		assert_eq!(tenant.quota_bytes, Some(1_073_741_824));
		assert_eq!(tenant.max_accounts, Some(50));
		assert_eq!(tenant.max_domains, Some(5));
		assert_eq!(tenant.submission_rate_limit_per_min, Some(200));
	}

	#[test]
	fn parses_minimal_tenant() {
		let tenant: Tenant = toml::from_str(
			r#"
domains = ["only.example"]
"#,
		)
		.expect("parse minimal tenant");
		assert_eq!(tenant.name, None);
		assert_eq!(tenant.domains, vec!["only.example".to_string()]);
		assert_eq!(tenant.quota_bytes, None);
		assert_eq!(tenant.max_accounts, None);
		assert_eq!(tenant.max_domains, None);
		assert_eq!(tenant.submission_rate_limit_per_min, None);
	}

	#[test]
	fn rejects_unknown_keys() {
		let result: Result<Tenant, _> = toml::from_str(
			r#"
domains = ["only.example"]
surprise = true
"#,
		);
		assert!(result.is_err());
	}
