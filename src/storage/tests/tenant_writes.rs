//! New mail of an account in a keyed tenant lands under the tenant key once
//! `[storage] tenant_keys` is on, and under the server key otherwise.

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use super::delivery::LocalDelivery;
use crate::config::{Storage, Tenant};
use crate::directory_store::DirectoryHandle;
use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::MessageSink;
use crate::storage::{
	EnvelopeKind, KeyOwner, MessageCrypto, envelope_kind as kind, generate_key_base64,
};

const BODY: &[u8] = b"Subject: tenant\r\n\r\nfor acme only\r\n";

fn directory() -> DirectoryHandle {
	DirectoryHandle::new(crate::smtp::directory::Directory::new(
		["acme.test".to_string(), "plain.test".to_string()],
		[
			("alice@acme.test".to_string(), "alice".to_string()),
			("bob@plain.test".to_string(), "bob".to_string()),
		],
	))
}

fn key_file(dir: &std::path::Path, name: &str) -> std::path::PathBuf {
	let path = dir.join(name);
	std::fs::write(&path, generate_key_base64().expect("csprng")).expect("key");
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
	path
}

fn crypto(keys: &std::path::Path, tenant_keys: bool) -> MessageCrypto {
	let storage = Storage {
		encrypt_at_rest: true,
		tenant_keys,
		encryption_key_file: Some(key_file(keys, "server.key")),
		..Storage::default()
	};
	let tenants = [Tenant {
		name: Some("acme".into()),
		domains: vec!["acme.test".into()],
		quota_bytes: None,
		max_accounts: None,
		max_domains: None,
		submission_rate_limit_per_min: None,
		encryption_key_file: Some(key_file(keys, "acme.key")),
	}];
	let crypto = MessageCrypto::from_parts(Some(&storage), &tenants).expect("crypto");
	crypto.attach_accounts(Arc::new(directory()));
	crypto
}

fn message(to: &str) -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: "sender@elsewhere.example".into(),
		recipients: vec![to.into()],
		data: BODY.to_vec(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: false,
		no_dsn: Vec::new(),
	}
}

fn stored(data: &std::path::Path, account: &str) -> Vec<u8> {
	let dir = data.join("accounts").join(account).join("new");
	let entry = std::fs::read_dir(&dir)
		.expect("new/")
		.flatten()
		.find(|entry| entry.path().extension().is_some_and(|ext| ext == "eml"))
		.expect("one message");
	std::fs::read(entry.path()).expect("read")
}

fn acme_id(crypto: &MessageCrypto) -> crate::storage::KeyId {
	crypto
		.key_listing()
		.into_iter()
		.find(|(owner, _)| *owner == KeyOwner::Tenant("acme".into()))
		.map(|(_, id)| id)
		.expect("acme key")
}

#[test]
fn delivery_to_a_tenant_account_uses_the_tenant_key() {
	let data = tempfile::tempdir().expect("data");
	let keys = tempfile::tempdir().expect("keys");
	let crypto = crypto(keys.path(), true);
	let delivery =
		LocalDelivery::new_with_crypto(data.path(), directory(), crypto.clone()).expect("delivery");
	delivery.deliver(message("alice@acme.test")).expect("alice");
	delivery.deliver(message("bob@plain.test")).expect("bob");

	let alice = stored(data.path(), "alice");
	assert_eq!(kind(&alice), EnvelopeKind::V2(acme_id(&crypto)));
	assert!(crypto.decode(&alice).expect("open").ends_with(BODY));
	let bob = stored(data.path(), "bob");
	assert_eq!(kind(&bob), EnvelopeKind::V1, "no tenant: the server key");

	// The IMAP read path opens the tenant envelope transparently.
	let snapshot = crate::imap::mailbox::Snapshot::open(data.path(), "alice", "INBOX", &crypto)
		.expect("snapshot");
	let first = snapshot.messages().next().expect("one message");
	assert!(snapshot.read(first).expect("read").ends_with(BODY));
}

#[test]
fn an_imap_append_uses_the_tenant_key_too() {
	let data = tempfile::tempdir().expect("data");
	let keys = tempfile::tempdir().expect("keys");
	let crypto = crypto(keys.path(), true);
	crate::imap::mailbox::ensure_defaults(data.path(), "alice").expect("mailbox");
	crate::imap::mailbox::append(data.path(), "alice", "INBOX", &[], BODY, &crypto)
		.expect("append");
	let alice = stored(data.path(), "alice");
	assert_eq!(kind(&alice), EnvelopeKind::V2(acme_id(&crypto)));
}

#[test]
fn without_tenant_keys_on_every_write_stays_on_the_server_key() {
	let data = tempfile::tempdir().expect("data");
	let keys = tempfile::tempdir().expect("keys");
	let crypto = crypto(keys.path(), false);
	let delivery =
		LocalDelivery::new_with_crypto(data.path(), directory(), crypto.clone()).expect("delivery");
	delivery.deliver(message("alice@acme.test")).expect("alice");
	assert_eq!(kind(&stored(data.path(), "alice")), EnvelopeKind::V1);
	assert_eq!(
		crypto.write_owner_for_account("alice"),
		Some(KeyOwner::Server)
	);
}
