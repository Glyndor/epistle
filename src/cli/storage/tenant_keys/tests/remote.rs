//! Remote objects must not acquire tenant envelopes without a migration path.

use super::owners::{config, invoke};
use super::*;
use crate::storage::EnvelopeKind;
use crate::storage::rekey::tests::fixture::{Fixture, fixture};
use std::path::PathBuf;

fn s3(fx: &Fixture, tenant_config: bool, writes: bool) -> PathBuf {
	let path = config(fx, "", true, tenant_config);
	let secret = fx.data_dir().join("s3-secret");
	std::fs::write(&secret, "fixture-secret").unwrap();
	std::fs::set_permissions(&secret, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
	let text = std::fs::read_to_string(&path).unwrap().replace(
		&format!("tenant_keys = {tenant_config}"),
		&format!("tenant_keys = {writes}"),
	);
	std::fs::write(&path, format!("{text}\n[storage.blobs]\nbackend = 's3'\nendpoint = 'https://s3.example.org'\nbucket = 'fixture'\nregion = 'us-east-1'\naccess_key_id = 'fixture'\nsecret_access_key_file = {secret:?}\n")).unwrap();
	path
}

fn rejects_writes(tenant_config: bool) {
	let fx = fixture();
	let path = s3(&fx, tenant_config, true);
	let error = Config::load(&path)
		.expect_err("S3 tenant writes must fail configuration validation")
		.to_string();
	assert!(
		error.contains("tenant_keys") && error.contains("S3"),
		"{error}"
	);
}

#[test]
fn tk05_s3_rejects_tenant_writes_in_config_validation() {
	rejects_writes(true);
}
#[test]
fn tk05_s3_rejects_tenant_writes_even_without_a_tenant_key() {
	rejects_writes(false);
}

#[test]
fn tk05_crypto_construction_also_refuses_s3_tenant_writes() {
	let fx = fixture();
	let path = s3(&fx, true, true);
	// Directly deserialized configurations bypass Config::load validation.
	let raw: Config = toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
	match MessageCrypto::from_full_config(&raw) {
		Ok(_) => panic!("crypto construction enabled unsupported S3 tenant writes"),
		Err(error) => assert!(
			error.to_string().contains("S3") && error.to_string().contains("tenant_keys"),
			"{error}"
		),
	}
}

fn refuses_migration(rollback: bool, dry_run: bool) {
	let fx = fixture();
	let bytes = if rollback {
		fx.crypto()
			.seal_for(&KeyOwner::Tenant("acme".into()), b"private")
			.unwrap()
	} else {
		fx.server_only().encode(b"server owned").unwrap()
	};
	let mail = fx.write_raw("alice", "new/one.eml", &bytes);
	let path = s3(&fx, rollback, false);
	Config::load(&path).expect("server-only S3 writes remain supported");
	let (code, status) = invoke(&path, rollback, dry_run);
	assert_eq!(
		code,
		ExitCode::FAILURE,
		"a local-only pass cannot complete an S3 migration: {status}"
	);
	assert!(
		status.contains("S3") && status.contains("migration"),
		"{status}"
	);
	assert_eq!(
		std::fs::read(mail).unwrap(),
		bytes,
		"refusal must precede local rewrites"
	);
	assert_eq!(journal::read(fx.data_dir()).unwrap(), None);
}

#[test]
fn tk05_s3_rollback_refuses_a_partial_migration() {
	refuses_migration(true, false);
}
#[test]
fn tk05_s3_rotation_refuses_a_partial_migration() {
	refuses_migration(false, false);
}
#[test]
fn tk05_s3_dry_run_refuses_a_partial_inventory() {
	refuses_migration(false, true);
}

#[test]
fn tk05_s3_server_only_writes_remain_supported() {
	let fx = fixture();
	let path = s3(&fx, false, false);
	let config = Config::load(&path).unwrap();
	let crypto = MessageCrypto::from_full_config(&config).unwrap();
	let stored = crypto
		.encode_for_account("alice", b"server upload")
		.unwrap();
	assert_eq!(crate::storage::envelope_kind(&stored), EnvelopeKind::V1);
	assert_eq!(crypto.decode(&stored).unwrap(), b"server upload");
}

#[test]
fn tk05_explicit_filesystem_tenant_writes_remain_supported() {
	let fx = fixture();
	let path = config(&fx, "", true, true);
	let text = std::fs::read_to_string(&path).unwrap();
	std::fs::write(&path, format!("{text}\n[storage.blobs]\nbackend = 'fs'\n")).unwrap();
	let config = Config::load(&path).unwrap();
	let crypto = MessageCrypto::from_full_config(&config).unwrap();
	crate::cli::util::attach_file_accounts(&crypto, &config).unwrap();
	let stored = crypto
		.encode_for_account("alice", b"tenant upload")
		.unwrap();
	assert_eq!(
		crypto.open_owned(&stored).unwrap(),
		(b"tenant upload".to_vec(), KeyOwner::Tenant("acme".into()))
	);
}
