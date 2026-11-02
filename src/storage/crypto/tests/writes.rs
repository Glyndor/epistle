//! Which key a write for an account picks.

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use super::*;
use crate::config::{Storage, Tenant};

struct Table;

impl AccountAddresses for Table {
	fn addresses_for(&self, account: &str) -> Vec<String> {
		match account {
			"alice" => vec!["alice@acme.test".into(), "a@acme-mail.test".into()],
			"carol" => vec!["c@acme.test".into(), "c@globex.test".into()],
			"dave" => vec!["dave@globex.test".into()],
			_ => Vec::new(),
		}
	}
}

fn key(dir: &std::path::Path, name: &str) -> std::path::PathBuf {
	let path = dir.join(name);
	std::fs::write(&path, generate_key_base64().expect("csprng")).expect("key");
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
	path
}

fn tenant(name: &str, domains: &[&str], key: Option<std::path::PathBuf>) -> Tenant {
	Tenant {
		name: Some(name.into()),
		domains: domains.iter().map(|domain| (*domain).into()).collect(),
		quota_bytes: None,
		max_accounts: None,
		max_domains: None,
		submission_rate_limit_per_min: None,
		encryption_key_file: key,
	}
}

fn crypto(enabled: bool, tenant_keys: bool) -> (tempfile::TempDir, MessageCrypto) {
	let dir = tempfile::tempdir().expect("tempdir");
	let storage = Storage {
		encrypt_at_rest: enabled,
		tenant_keys,
		encryption_key_file: Some(key(dir.path(), "server.key")),
		..Storage::default()
	};
	let tenants = [
		tenant(
			"acme",
			&["acme.test", "acme-mail.test"],
			Some(key(dir.path(), "acme.key")),
		),
		tenant("globex", &["globex.test"], None),
	];
	let crypto = MessageCrypto::from_parts(Some(&storage), &tenants).expect("crypto");
	(dir, crypto)
}

fn acme() -> KeyOwner {
	KeyOwner::Tenant("acme".into())
}

#[test]
fn an_account_whose_domains_are_all_in_one_keyed_tenant_writes_under_its_key() {
	let (_dir, crypto) = crypto(true, true);
	crypto.attach_accounts(Arc::new(Table));
	assert_eq!(crypto.write_owner_for_account("alice"), Some(acme()));
	let sealed = crypto.encode_for_account("alice", b"x").expect("seal");
	assert!(matches!(kind(&sealed), EnvelopeKind::V2(_)));
}

#[test]
fn an_account_across_two_tenants_stays_on_the_server_key() {
	let (_dir, crypto) = crypto(true, true);
	crypto.attach_accounts(Arc::new(Table));
	assert_eq!(
		crypto.write_owner_for_account("carol"),
		Some(KeyOwner::Server)
	);
	let sealed = crypto.encode_for_account("carol", b"x").expect("seal");
	assert_eq!(kind(&sealed), EnvelopeKind::V1);
}

#[test]
fn a_tenant_without_a_key_and_an_account_in_no_tenant_use_the_server_key() {
	let (_dir, crypto) = crypto(true, true);
	crypto.attach_accounts(Arc::new(Table));
	assert_eq!(
		crypto.write_owner_for_account("dave"),
		Some(KeyOwner::Server)
	);
	assert_eq!(
		crypto.write_owner_for_account("eve"),
		Some(KeyOwner::Server)
	);
}

#[test]
fn tenant_keys_off_or_no_account_map_keep_the_server_key() {
	let (_dir, off) = crypto(true, false);
	off.attach_accounts(Arc::new(Table));
	assert!(!off.tenant_writes());
	assert_eq!(off.write_owner_for_account("alice"), Some(KeyOwner::Server));
	let (_dir, unmapped) = crypto(true, true);
	assert_eq!(
		unmapped.write_owner_for_account("alice"),
		Some(KeyOwner::Server)
	);
}

#[test]
fn with_encryption_off_a_write_is_plaintext_whatever_the_tenant() {
	let (_dir, crypto) = crypto(false, true);
	crypto.attach_accounts(Arc::new(Table));
	assert!(!crypto.tenant_writes(), "tenant writes need encryption on");
	assert_eq!(crypto.write_owner_for_account("alice"), None);
	assert_eq!(
		crypto.encode_for_account("alice", b"x").expect("plain"),
		b"x"
	);
}

#[test]
fn a_retired_key_is_never_a_target() {
	let (_dir, crypto) = crypto(true, true);
	assert!(crypto.seal_for(&KeyOwner::Retired(0), b"x").is_err());
}
