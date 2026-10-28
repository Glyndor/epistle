	use super::*;

	#[test]
	fn defaults_max_connections() {
		let db: Database = toml::from_str(r#"url = "postgres://localhost/mail""#).expect("parse");
		assert_eq!(db.max_connections, 10);
		assert_eq!(db.url, "postgres://localhost/mail");
		assert!(!db.directory);
		assert_eq!(db.tls, DatabaseTls::Require);
	}

	#[test]
	fn parses_directory_flag() {
		let db: Database =
			toml::from_str("url = \"postgres://localhost/mail\"\ndirectory = true\n")
				.expect("parse");
		assert!(db.directory);
	}

	#[test]
	fn parses_insecure_tls_opt_in() {
		let db: Database = toml::from_str(
			r#"url = "postgres://localhost/mail"
tls = "insecure"
"#,
		)
		.expect("parse");
		assert_eq!(db.tls, DatabaseTls::Insecure);
	}

	#[test]
	fn rejects_unknown_keys() {
		let result: Result<Database, _> =
			toml::from_str("url = \"postgres://x\"\nsurprise = true\n");
		assert!(result.is_err());
	}

	#[test]
	fn rejects_unknown_tls_value() {
		// Only `require` (default) and `insecure` are accepted; a typo is not
		// silently coerced to one of them.
		let result: Result<Database, _> =
			toml::from_str("url = \"postgres://localhost/mail\"\ntls = \"maybe\"\n");
		assert!(result.is_err(), "unknown tls value must be rejected");
	}

	#[test]
	fn parses_password_file() {
		let db: Database = toml::from_str(
			r#"url = "postgres://epistle@%2Frun%2Fpostgresql/epistle"
password_file = "/run/secrets/epistle_db_password"
"#,
		)
		.expect("parse");
		assert_eq!(
			db.password_file,
			Some(PathBuf::from("/run/secrets/epistle_db_password"))
		);
	}

	#[test]
	fn password_file_defaults_to_none() {
		let db: Database = toml::from_str(r#"url = "postgres://localhost/mail""#).expect("parse");
		assert!(db.password_file.is_none());
	}
