//! Key provisioning and writes with a read-only configuration file.

use super::fixture::*;
use super::writes::{call, disk, loaded};
use axum::http::StatusCode;
use serde_json::json;

#[tokio::test]
async fn domain_add_provisions_own_keys_or_explicitly_shares_the_default() {
	let dir = tempfile::tempdir().unwrap();
	let key_path = dir.path().join("default.pem");
	let (pem, _) = crate::dkim::generate_key().unwrap();
	std::fs::write(&key_path, pem).unwrap();
	let world = world_with(&format!(
		"[dkim]\nselector = 's1'\nkey_file = {key_path:?}\n"
	));
	for (domain, shared) in [("own.example", false), ("shared.example", true)] {
		let (status, body) = call(
			&world,
			"POST",
			"/api/v1/domains",
			WRITER,
			Some(json!({"domain":domain,"shared_dkim_key":shared})),
		)
		.await;
		assert_eq!(status, StatusCode::CREATED, "{body}");
		assert!(!body.to_string().contains("srs_secret"));
	}
	let file = disk(&world);
	let own = file.domain("own.example").unwrap();
	let shared = file.domain("shared.example").unwrap();
	let key = own.dkim.as_ref().unwrap();
	assert!(key.key_file.starts_with(world.state.data_dir()));
	assert!(key.key_file.is_file());
	assert!(crate::dkim::Signer::load(&key.selector, &key.key_file).is_ok());
	assert!(shared.dkim.is_none());
	assert_ne!(own.srs_secret, shared.srs_secret);
	let before = file.clone();
	let (status, _) = call(
		&world,
		"POST",
		"/api/v1/domains",
		WRITER,
		Some(json!({"domain":"own.example"})),
	)
	.await;
	assert_eq!(status, StatusCode::CONFLICT);
	assert_eq!(disk(&world), before);
}

#[cfg(unix)]
#[tokio::test]
async fn domain_changes_work_with_a_read_only_configuration_file() {
	use std::os::unix::fs::{MetadataExt, PermissionsExt};
	let world = world();
	let path = world._dir.path().join("mail.toml");
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
	let before = std::fs::read(&path).unwrap();
	let ino = std::fs::metadata(&path).unwrap().ino();
	let (status, body) = call(
		&world,
		"PUT",
		"/api/v1/domains/a.example",
		WRITER,
		Some(json!({"role":"receive-only","quota":0,"submission_rate":2})),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let config = loaded(&world);
	assert_eq!(config.domain_quotas["a.example"], 0);
	assert_eq!(config.domain_submission_limits["a.example"], 2);
	assert_eq!(std::fs::read(&path).unwrap(), before);
	assert_eq!(std::fs::metadata(path).unwrap().ino(), ino);
}
