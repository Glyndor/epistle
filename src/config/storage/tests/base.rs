	use super::*;

	#[test]
	fn defaults_to_disabled() {
		let storage: Storage = toml::from_str("").expect("parse empty");
		assert!(!storage.encrypt_at_rest);
		assert!(storage.encryption_key_env.is_none());
		assert!(storage.encryption_key_file.is_none());
		// The current behaviour is the default: zero days retention, so
		// expunge deletes in the act.
		assert_eq!(storage.deleted_retention_days, 0);
		// The delivery log keeps 30 days unless the operator says otherwise.
		assert_eq!(storage.delivery_log_days, DEFAULT_DELIVERY_LOG_DAYS);
		// No `[storage.blobs]` section → no override.
		assert!(storage.blobs.is_none());
	}

	#[test]
	fn parses_key_sources() {
		let storage: Storage = toml::from_str(
			r#"
encrypt_at_rest = true
encryption_key_env = "EPISTLE_STORAGE_KEY"
encryption_key_file = "/etc/epistle/mail.key"
"#,
		)
		.expect("parse");
		assert!(storage.encrypt_at_rest);
		assert_eq!(
			storage.encryption_key_env.as_deref(),
			Some("EPISTLE_STORAGE_KEY")
		);
		assert_eq!(
			storage.encryption_key_file.as_deref(),
			Some(std::path::Path::new("/etc/epistle/mail.key"))
		);
	}

	#[test]
	fn parses_retention_days() {
		let storage: Storage = toml::from_str("deleted_retention_days = 30").expect("parse");
		assert_eq!(storage.deleted_retention_days, 30);
	}

	#[test]
	fn parses_delivery_log_days() {
		let storage: Storage = toml::from_str("delivery_log_days = 14").expect("parse");
		assert_eq!(storage.delivery_log_days, 14);
	}

	#[test]
	fn rejects_unknown_keys() {
		assert!(toml::from_str::<Storage>(r#"encrypt = true"#).is_err());
	}

	#[test]
	fn blobs_section_is_optional() {
		// A config without `[storage.blobs]` parses: the historical
		// behaviour (blobs on disk) is the default.
		let storage: Storage = toml::from_str("").expect("parse empty");
		assert!(storage.blobs.is_none());
	}

	#[test]
	fn blobs_fs_backend_parses() {
		let storage: Storage = toml::from_str(
			r#"[blobs]
backend = "fs"
"#,
		)
		.expect("parse fs");
		match storage.blobs.expect("blobs set") {
			BlobBackendConfig::Fs => {}
			BlobBackendConfig::S3(_) => panic!("expected fs"),
		}
	}

	#[test]
	fn blobs_s3_backend_parses_with_env_secret() {
		let storage: Storage = toml::from_str(
			r#"[blobs]
backend = "s3"
endpoint = "https://s3.us-east-1.amazonaws.com"
bucket = "mail-blobs"
region = "us-east-1"
access_key_id = "AKIA-EXAMPLE"
secret_access_key_env = "EPISTLE_S3_SECRET"
"#,
		)
		.expect("parse s3");
		let BlobBackendConfig::S3(s3) = storage.blobs.expect("blobs set") else {
			panic!("expected s3");
		};
		assert_eq!(s3.endpoint, "https://s3.us-east-1.amazonaws.com");
		assert_eq!(s3.bucket, "mail-blobs");
		assert_eq!(s3.region, "us-east-1");
		assert_eq!(s3.access_key_id, "AKIA-EXAMPLE");
		assert_eq!(
			s3.secret_access_key_env.as_deref(),
			Some("EPISTLE_S3_SECRET")
		);
		assert!(s3.secret_access_key_file.is_none());
	}

	#[test]
	fn blobs_s3_backend_rejects_inline_secret() {
		// A literal secret in the config is rejected at the wire level: the
		// schema only knows the env / file shapes, so `secret_access_key =
		// "..."` comes back as an unknown key under `deny_unknown_fields`.
		let result = toml::from_str::<Storage>(
			r#"[blobs]
backend = "s3"
endpoint = "https://s3.us-east-1.amazonaws.com"
bucket = "mail-blobs"
region = "us-east-1"
access_key_id = "AKIA-EXAMPLE"
secret_access_key = "literal-should-not-be-allowed"
"#,
		);
		assert!(
			result.is_err(),
			"a literal secret_access_key must fail to parse"
		);
	}
