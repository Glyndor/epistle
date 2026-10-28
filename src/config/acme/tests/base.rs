	use super::*;

	#[test]
	fn parses_with_defaults() {
		let acme: Acme = toml::from_str(
			r#"
directory_url = "https://acme-v02.api.letsencrypt.org/directory"
domains = ["mail.example.org"]
"#,
		)
		.expect("parse");
		assert_eq!(acme.renew_before_days, 30);
		assert!(acme.contacts.is_empty());
		assert_eq!(acme.domains, vec!["mail.example.org".to_string()]);
	}

	#[test]
	fn rejects_unknown_keys() {
		let result: Result<Acme, _> = toml::from_str(
			"directory_url = \"https://x/dir\"\ndomains = [\"a.example\"]\nsurprise = true\n",
		);
		assert!(result.is_err());
	}
