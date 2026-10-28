	use super::*;

	#[test]
	fn parses_with_default_service_name() {
		let otel: Otel = toml::from_str(r#"endpoint = "http://localhost:4318""#).expect("parse");
		assert_eq!(otel.endpoint, "http://localhost:4318");
		assert_eq!(otel.service_name, "epistle");
	}

	#[test]
	fn service_name_overrides_default() {
		let otel: Otel = toml::from_str(
			r#"
endpoint = "http://collector:4318"
service_name = "epistle-mx"
"#,
		)
		.expect("parse");
		assert_eq!(otel.service_name, "epistle-mx");
	}

	#[test]
	fn rejects_missing_endpoint_and_unknown_keys() {
		assert!(toml::from_str::<Otel>(r#"service_name = "x""#).is_err());
		assert!(
			toml::from_str::<Otel>(
				r#"endpoint = "u"
extra = 1"#
			)
			.is_err()
		);
	}
