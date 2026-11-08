//! Tenant keys, version 2 envelopes and reading what version 1 wrote.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use super::*;
use crate::config::{Storage, Tenant};

/// A fresh key, generated at run time so no key sits in the source.
fn fresh_key() -> String {
	generate_key_base64().expect("csprng")
}

fn key_file(dir: &Path, name: &str, key: &str, mode: u32) -> PathBuf {
	let path = dir.join(name);
	std::fs::write(&path, key).expect("write key");
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
	path
}

fn storage(server: &Path, enabled: bool) -> Storage {
	Storage {
		encrypt_at_rest: enabled,
		encryption_key_file: Some(server.to_path_buf()),
		..Storage::default()
	}
}

fn tenant(name: &str, domain: &str, key: Option<PathBuf>) -> Tenant {
	Tenant {
		name: Some(name.into()),
		domains: vec![domain.into()],
		quota_bytes: None,
		max_accounts: None,
		max_domains: None,
		submission_rate_limit_per_min: None,
		encryption_key_file: key,
		webhook: None,
	}
}

/// A server key and two tenants, each with its own key file.
struct Fixture {
	_dir: tempfile::TempDir,
	server: PathBuf,
	acme: PathBuf,
	globex: PathBuf,
}

fn fixture() -> Fixture {
	let dir = tempfile::tempdir().expect("tempdir");
	let server = key_file(dir.path(), "server.key", &fresh_key(), 0o600);
	let acme = key_file(dir.path(), "acme.key", &fresh_key(), 0o600);
	let globex = key_file(dir.path(), "globex.key", &fresh_key(), 0o600);
	Fixture {
		_dir: dir,
		server,
		acme,
		globex,
	}
}

fn crypto_with(fx: &Fixture, tenants: &[Tenant]) -> MessageCrypto {
	MessageCrypto::from_parts(Some(&storage(&fx.server, true)), tenants).expect("crypto")
}

fn acme() -> Owner {
	KeyOwner::Tenant("acme".into())
}

type Owner = KeyOwner;

#[test]
fn a_tenant_envelope_names_its_key_and_reads_back() {
	let fx = fixture();
	let crypto = crypto_with(&fx, &[tenant("acme", "acme.test", Some(fx.acme.clone()))]);
	let sealed = crypto
		.seal_v2_for(&acme(), b"tenant mail", &[])
		.expect("seal");
	let id = crypto
		.key_listing()
		.into_iter()
		.find(|(owner, _)| *owner == acme())
		.map(|(_, id)| id)
		.expect("acme key listed");
	assert_eq!(kind(&sealed), EnvelopeKind::V2(id));
	assert_eq!(sealed.len(), b"tenant mail".len() + OVERHEAD_V2);
	assert_eq!(crypto.decode(&sealed).expect("decode"), b"tenant mail");
}

#[test]
fn the_same_key_file_gives_the_same_id_on_every_load() {
	let fx = fixture();
	let tenants = [tenant("acme", "acme.test", Some(fx.acme.clone()))];
	let first = crypto_with(&fx, &tenants).key_listing();
	let second = crypto_with(&fx, &tenants).key_listing();
	assert_eq!(first, second);
	assert_ne!(first[0].1, first[1].1, "server and tenant ids differ");
}

#[test]
fn another_tenants_key_cannot_open_a_tenant_envelope() {
	let fx = fixture();
	let writer = crypto_with(&fx, &[tenant("acme", "acme.test", Some(fx.acme.clone()))]);
	let sealed = writer
		.seal_v2_for(&acme(), b"acme only", &[])
		.expect("seal");
	// A process holding the server key and globex's key, but not acme's.
	let other = crypto_with(
		&fx,
		&[tenant("globex", "globex.test", Some(fx.globex.clone()))],
	);
	let error = other.decode(&sealed).expect_err("acme's mail stays closed");
	assert!(error.to_string().contains("which is not loaded"));
	// Rewriting the header to name globex's key does not help: the tag fails.
	let globex_id = other
		.key_listing()
		.into_iter()
		.find(|(owner, _)| *owner == KeyOwner::Tenant("globex".into()))
		.map(|(_, id)| id)
		.expect("globex listed");
	let mut forged = sealed.clone();
	forged[MAGIC_V2.len()..MAGIC_V2.len() + keyring::KEY_ID_LEN]
		.copy_from_slice(globex_id.as_bytes());
	assert!(matches!(
		other.decode_with_aad(&forged, &[]),
		Err(CryptoAuthError::AuthenticationFailed)
	));
}

#[test]
fn the_server_key_cannot_open_a_tenant_envelope() {
	let fx = fixture();
	let writer = crypto_with(&fx, &[tenant("acme", "acme.test", Some(fx.acme.clone()))]);
	let sealed = writer
		.seal_v2_for(&acme(), b"acme only", &[])
		.expect("seal");
	let server_only = crypto_with(&fx, &[]);
	assert!(server_only.decode(&sealed).is_err());
}

/// A version 1 envelope built with `ring` directly, the way the code before
/// tenant keys wrote it, so the check does not go through the new writer.
fn legacy_v1(raw_key: &[u8], plaintext: &[u8]) -> Vec<u8> {
	use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
	let key = LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, raw_key).expect("key"));
	let mut nonce = [0u8; 12];
	ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut nonce).expect("rng");
	let mut buffer = plaintext.to_vec();
	key.seal_in_place_append_tag(
		Nonce::assume_unique_for_key(nonce),
		Aad::empty(),
		&mut buffer,
	)
	.expect("seal");
	[MAGIC, &nonce[..], &buffer[..]].concat()
}

#[test]
fn files_written_before_tenant_keys_still_read_with_them_loaded() {
	let fx = fixture();
	let raw = decode_key_text(std::fs::read_to_string(&fx.server).expect("read").trim())
		.expect("server key");
	let old = legacy_v1(&raw, b"written by 0.12.6");
	let crypto = crypto_with(
		&fx,
		&[
			tenant("acme", "acme.test", Some(fx.acme.clone())),
			tenant("globex", "globex.test", Some(fx.globex.clone())),
		],
	);
	assert_eq!(crypto.decode(&old).expect("v1 reads"), b"written by 0.12.6");
	// And the server key still writes version 1 until tenant writes are on.
	assert_eq!(
		kind(&crypto.encode(b"new").expect("encode")),
		EnvelopeKind::V1
	);
}

#[test]
fn two_tenants_with_the_same_key_are_refused() {
	let fx = fixture();
	let error = MessageCrypto::from_parts(
		Some(&storage(&fx.server, true)),
		&[
			tenant("acme", "acme.test", Some(fx.acme.clone())),
			tenant("globex", "globex.test", Some(fx.acme.clone())),
		],
	)
	.expect_err("shared key refused");
	assert!(matches!(error, CryptoError::DuplicateKey { .. }));
	assert!(error.to_string().contains("\"acme\""));
	assert!(error.to_string().contains("\"globex\""));
}

#[test]
fn a_tenant_reusing_the_server_key_is_refused() {
	let fx = fixture();
	let error = MessageCrypto::from_parts(
		Some(&storage(&fx.server, true)),
		&[tenant("acme", "acme.test", Some(fx.server.clone()))],
	)
	.expect_err("server key reuse refused");
	assert!(matches!(error, CryptoError::DuplicateKey { .. }));
}

#[test]
fn a_tenant_key_file_readable_by_others_is_refused() {
	let fx = fixture();
	std::fs::set_permissions(&fx.acme, std::fs::Permissions::from_mode(0o644)).expect("chmod");
	let error = MessageCrypto::from_parts(
		Some(&storage(&fx.server, true)),
		&[tenant("acme", "acme.test", Some(fx.acme.clone()))],
	)
	.expect_err("loose mode refused");
	assert!(matches!(error, CryptoError::KeyFilePermissions { .. }));
}

#[test]
fn a_missing_tenant_key_file_stops_the_load() {
	let fx = fixture();
	let gone = fx.acme.with_file_name("gone.key");
	let error = MessageCrypto::from_parts(
		Some(&storage(&fx.server, true)),
		&[tenant("acme", "acme.test", Some(gone))],
	)
	.expect_err("missing file refused");
	assert!(matches!(error, CryptoError::KeyFile { .. }));
}

#[test]
fn a_tenant_key_needs_a_name_and_a_server_key() {
	let fx = fixture();
	let mut unnamed = tenant("acme", "acme.test", Some(fx.acme.clone()));
	unnamed.name = None;
	assert!(matches!(
		MessageCrypto::from_parts(Some(&storage(&fx.server, true)), &[unnamed]),
		Err(CryptoError::TenantUnnamed)
	));
	let keyed = [tenant("acme", "acme.test", Some(fx.acme.clone()))];
	assert!(matches!(
		MessageCrypto::from_parts(None, &keyed),
		Err(CryptoError::TenantWithoutServerKey)
	));
	assert!(matches!(
		MessageCrypto::from_parts(Some(&Storage::default()), &keyed),
		Err(CryptoError::TenantWithoutServerKey)
	));
}

#[test]
fn no_error_or_debug_output_carries_key_material() {
	let fx = fixture();
	let keys = [&fx.server, &fx.acme].map(|path| {
		std::fs::read_to_string(path)
			.expect("read")
			.trim()
			.to_string()
	});
	let shared = MessageCrypto::from_parts(
		Some(&storage(&fx.server, true)),
		&[tenant("acme", "acme.test", Some(fx.server.clone()))],
	)
	.expect_err("duplicate");
	let crypto = crypto_with(&fx, &[tenant("acme", "acme.test", Some(fx.acme.clone()))]);
	let printed = [
		format!("{shared}"),
		format!("{shared:?}"),
		format!("{crypto:?}"),
	];
	for text in printed {
		for key in &keys {
			assert!(!text.contains(key.as_str()), "a key leaked into a message");
		}
	}
}

#[test]
fn the_plaintext_length_of_a_version_2_file_drops_its_overhead() {
	let fx = fixture();
	let crypto = crypto_with(&fx, &[tenant("acme", "acme.test", Some(fx.acme.clone()))]);
	let path = fx.server.with_file_name("message.eml");
	let sealed = crypto
		.seal_v2_for(&acme(), b"twelve bytes", &[])
		.expect("seal");
	std::fs::write(&path, &sealed).expect("write");
	assert_eq!(crypto.stored_plaintext_len(&path, sealed.len() as u64), 12);
}

/// Addresses served from a fixed table, standing in for the directory.
struct Table(Vec<(&'static str, Vec<String>)>);

impl AccountAddresses for Table {
	fn addresses_for(&self, account: &str) -> Vec<String> {
		self.0
			.iter()
			.find(|(name, _)| *name == account)
			.map(|(_, addresses)| addresses.clone())
			.unwrap_or_default()
	}
}

#[test]
fn an_account_resolves_to_the_tenant_of_its_domains() {
	let fx = fixture();
	let crypto = crypto_with(
		&fx,
		&[
			tenant("acme", "acme.test", Some(fx.acme.clone())),
			tenant("globex", "globex.test", None),
		],
	);
	crypto.attach_accounts(std::sync::Arc::new(Table(vec![
		("alice", vec!["alice@ACME.test".into()]),
		("bob", vec!["bob@other.test".into()]),
		("carol", vec!["c@acme.test".into(), "c@globex.test".into()]),
	])));
	assert_eq!(
		crypto.tenant_of_account("alice"),
		TenantChoice::One("acme".into())
	);
	assert_eq!(crypto.tenant_of_account("bob"), TenantChoice::None);
	assert_eq!(
		crypto.tenant_of_account("carol"),
		TenantChoice::Several(vec!["acme".into(), "globex".into()])
	);
	assert_eq!(crypto.tenant_of_account("nobody"), TenantChoice::None);
}
