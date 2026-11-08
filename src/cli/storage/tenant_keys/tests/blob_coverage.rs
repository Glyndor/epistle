//! Blob storage may exist independently of mailbox directories.

use super::owners::{config, invoke};
use super::*;
use crate::config::Storage;
use crate::storage::rekey::tests::fixture::{Fixture, fixture};
use crate::storage::{BlobAccount, BlobBackend, EnvelopeKind, FsBackend};
use std::path::PathBuf;
use uuid::Uuid;

fn id() -> Uuid {
	Uuid::parse_str("01900000-0000-7000-8000-00000000abcd").unwrap()
}

fn rotation(fx: &Fixture) -> (PathBuf, MessageCrypto) {
	let path = config(fx, "", true, false);
	let text = std::fs::read_to_string(&path).unwrap().replace(
		&format!(
			"encryption_key_file = {:?}",
			fx.data_dir().join("server.key")
		),
		&format!(
			"encryption_key_file = {:?}\nretired_key_files = [{:?}]",
			fx.data_dir().join("globex.key"),
			fx.data_dir().join("server.key")
		),
	);
	std::fs::write(&path, text).unwrap();
	Config::load(&path).expect("valid rotation config");
	let current = MessageCrypto::from_config(Some(&Storage {
		encrypt_at_rest: true,
		encryption_key_file: Some(fx.data_dir().join("globex.key")),
		..Storage::default()
	}))
	.unwrap();
	(path, current)
}

fn shared(fx: &Fixture, bytes: &[u8], sharded: bool, owner: Option<&str>) -> PathBuf {
	let path = if sharded {
		crate::api::jmap::blob_path::write_path(fx.data_dir(), id(), "")
	} else {
		fx.data_dir().join("blobs").join(id().to_string())
	};
	std::fs::create_dir_all(path.parent().unwrap()).unwrap();
	std::fs::write(&path, bytes).unwrap();
	std::fs::write(path.with_extension("type"), b"application/octet-stream").unwrap();
	if let Some(owner) = owner {
		std::fs::write(path.with_extension("owner"), owner).unwrap();
	}
	path
}

#[tokio::test]
async fn tk04_rollback_covers_a_blob_only_account_partition() {
	let fx = fixture();
	let backend = FsBackend::new(fx.data_dir().to_path_buf());
	let account = BlobAccount::new("alice").unwrap();
	let sealed = fx
		.crypto()
		.seal_for(&KeyOwner::Tenant("acme".into()), b"upload only")
		.unwrap();
	backend.put(&account, id(), "", &sealed).await.unwrap();
	backend
		.put(&account, id(), ".owner", b"alice")
		.await
		.unwrap();
	assert!(!fx.data_dir().join("accounts/alice").exists());
	let path = config(&fx, "", true, true);
	let text = std::fs::read_to_string(&path)
		.unwrap()
		.replace("tenant_keys = true", "tenant_keys = false");
	std::fs::write(&path, text).unwrap();
	let (code, status) = invoke(&path, true, false);
	assert_eq!(code, ExitCode::SUCCESS, "{status}");
	let stored = backend.get(&account, id(), "").await.unwrap().unwrap();
	assert_eq!(
		crate::storage::envelope_kind(&stored),
		EnvelopeKind::V1,
		"rollback omitted the blob-only partition"
	);
	assert_eq!(fx.server_only().decode(&stored).unwrap(), b"upload only");
}

#[tokio::test]
async fn tk04_rotation_covers_a_blob_only_account_partition() {
	let fx = fixture();
	let backend = FsBackend::new(fx.data_dir().to_path_buf());
	let account = BlobAccount::new("alice").unwrap();
	let sealed = fx.server_only().encode(b"old-key upload").unwrap();
	backend.put(&account, id(), "", &sealed).await.unwrap();
	backend
		.put(&account, id(), ".owner", b"alice")
		.await
		.unwrap();
	assert!(!fx.data_dir().join("accounts/alice").exists());
	let (path, current) = rotation(&fx);
	let (code, status) = invoke(&path, false, false);
	assert_eq!(code, ExitCode::SUCCESS, "{status}");
	let stored = backend.get(&account, id(), "").await.unwrap().unwrap();
	assert_eq!(
		current
			.decode(&stored)
			.expect("blob-only upload must read without K1"),
		b"old-key upload"
	);
}

#[test]
fn tk04_rotation_covers_both_legacy_shared_copies() {
	let fx = fixture();
	let flat = shared(
		&fx,
		&fx.server_only().encode(b"flat").unwrap(),
		false,
		Some("alice"),
	);
	let sharded = shared(
		&fx,
		&fx.server_only().encode(b"sharded").unwrap(),
		true,
		Some("alice"),
	);
	let (path, current) = rotation(&fx);
	let (code, status) = invoke(&path, false, false);
	assert_eq!(code, ExitCode::SUCCESS, "{status}");
	for (file, body) in [(flat, &b"flat"[..]), (sharded, &b"sharded"[..])] {
		assert_eq!(
			current
				.decode(&std::fs::read(&file).unwrap())
				.expect("every legacy copy must read without K1"),
			body
		);
		assert_eq!(
			std::fs::read(file.with_extension("owner")).unwrap(),
			b"alice"
		);
		assert_eq!(
			std::fs::read(file.with_extension("type")).unwrap(),
			b"application/octet-stream"
		);
	}
}

#[test]
fn tk04_forward_migration_covers_legacy_shared_tenant_mail() {
	let fx = fixture();
	let blob = shared(
		&fx,
		&fx.server_only().encode(b"tenant upload").unwrap(),
		false,
		Some("alice"),
	);
	let path = config(&fx, "", true, true);
	let (code, status) = invoke(&path, false, false);
	assert_eq!(code, ExitCode::SUCCESS, "{status}");
	let stored = std::fs::read(blob).unwrap();
	assert_eq!(
		fx.crypto().open_owned(&stored).unwrap(),
		(b"tenant upload".to_vec(), KeyOwner::Tenant("acme".into()))
	);
	assert!(fx.server_only().decode(&stored).is_err());
}

#[test]
fn tk04_rollback_covers_legacy_shared_tenant_mail() {
	let fx = fixture();
	let sealed = fx
		.crypto()
		.seal_for(&KeyOwner::Tenant("acme".into()), b"tenant upload")
		.unwrap();
	let blob = shared(&fx, &sealed, true, Some("alice"));
	let path = config(&fx, "", true, true);
	std::fs::write(
		&path,
		std::fs::read_to_string(&path)
			.unwrap()
			.replace("tenant_keys = true", "tenant_keys = false"),
	)
	.unwrap();
	let (code, status) = invoke(&path, true, false);
	assert_eq!(code, ExitCode::SUCCESS, "{status}");
	let stored = std::fs::read(blob).unwrap();
	assert_eq!(
		crate::storage::envelope_kind(&stored),
		EnvelopeKind::V1,
		"shared rollback left V2 ciphertext"
	);
	assert_eq!(fx.server_only().decode(&stored).unwrap(), b"tenant upload");
}

#[test]
fn tk04_encrypted_shared_blob_without_an_owner_refuses_success() {
	let fx = fixture();
	let mail = fx.store("alice", "new/one.eml", b"mail");
	let before = std::fs::read(&mail).unwrap();
	let sealed = fx.server_only().encode(b"orphan upload").unwrap();
	let blob = shared(&fx, &sealed, false, None);
	let (path, _) = rotation(&fx);
	let (code, status) = invoke(&path, false, false);
	assert_eq!(
		code,
		ExitCode::FAILURE,
		"orphan encrypted blobs must block completion: {status}"
	);
	assert!(status.contains("owner"), "{status}");
	assert_eq!(std::fs::read(blob).unwrap(), sealed);
	assert_eq!(
		std::fs::read(mail).unwrap(),
		before,
		"preflight must precede rewrites"
	);
	assert_eq!(journal::read(fx.data_dir()).unwrap(), None);
}
