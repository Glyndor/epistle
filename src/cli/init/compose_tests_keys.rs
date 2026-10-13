//! The storage key and the OAuth signing key reach `mail` as compose
//! secrets, read-only, from a directory outside data_dir.

use super::render;
use super::*;
use serde_json::json;

#[test]
fn mail_reads_both_keys_as_secrets_at_their_host_paths() {
	for database in [false, true] {
		let mut answers = minimal_answers();
		answers.services.database = database;
		let value = render(&answers, database);
		let storage = "/var/lib/secrets/storage.key";
		let oauth = "/var/lib/secrets/oauth_signing.key";
		assert_eq!(
			value["secrets"]["epistle_storage_key"],
			json!({"file": storage})
		);
		assert_eq!(
			value["secrets"]["epistle_oauth_signing_key"],
			json!({"file": oauth})
		);
		let mounts = value["services"]["mail"]["secrets"]
			.as_array()
			.expect("mail secrets");
		for (source, target) in [
			("epistle_storage_key", storage),
			("epistle_oauth_signing_key", oauth),
		] {
			assert!(
				mounts.contains(&json!({
					"source": source,
					"target": target,
					"uid": "65532",
					"gid": "65532",
					"mode": 400
				})),
				"{source}: the host commands read the same config, so the path inside \
				 mail must be the host path: {mounts:?}"
			);
		}
	}
}

#[test]
fn no_other_service_gets_the_keys() {
	let value = render(&stack_answers(), true);
	for name in ["db", "clamav", "freshclam"] {
		let secrets = value["services"][name]["secrets"].to_string();
		assert!(
			!secrets.contains("storage_key") && !secrets.contains("oauth_signing"),
			"{name} must not mount the storage or OAuth signing key"
		);
	}
}

#[test]
fn the_keys_are_outside_every_bind_mount_of_mail() {
	let value = render(&stack_answers(), true);
	let secrets_dir = super::super::host_secrets::dir(&stack_answers().data_dir);
	for volume in value["services"]["mail"]["volumes"].as_array().unwrap() {
		if let Some(source) = volume["source"].as_str() {
			assert!(
				!secrets_dir.starts_with(source),
				"{source} would expose {} to mail read-write or whole",
				secrets_dir.display()
			);
		}
	}
}
