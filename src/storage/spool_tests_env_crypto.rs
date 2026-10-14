//! Envelope at-rest encryption and migration of legacy plaintext envelopes.
//!
//! With `encrypt_at_rest = true` the spool binds each `<id>.json` envelope to
//! the message id with the same ChaCha20-Poly1305 key as the body, so an
//! envelope cannot be swapped onto another message's body. A spool created
//! before encryption was turned on is migrated on first read: the plaintext
//! is rewritten encrypted (and atomically renamed in place) so subsequent
//! loads go through the AEAD. Tampering or attaching the wrong envelope id
//! must fail closed.

use std::collections::BTreeMap;

use uuid::Uuid;

use super::{Envelope, FsSpool};
use crate::config::Storage;
use crate::smtp::session::AcceptedMessage;
use crate::storage::crypto::MessageCrypto;

fn key() -> [u8; 32] {
	[7u8; 32]
}

fn sample() -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: "alice@example.org".into(),
		recipients: vec!["bob@example.org".into()],
		data: b"Subject: sealed\r\n\r\nsecret body\r\n".to_vec(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: false,
		no_dsn: Vec::new(),
	}
}

/// With encryption on, the `.json` sidecar is on-disk sealed (starts with the
/// envelope magic) and round-trips through `load`.
#[test]
fn encrypt_at_rest_seals_the_envelope() {
	let dir = tempfile::tempdir().expect("tempdir");
	let crypto = MessageCrypto::for_test(&key());
	let spool = FsSpool::open_with_crypto(dir.path(), crypto).expect("open");
	let id = spool
		.store(&sample(), None, &BTreeMap::new())
		.expect("store");

	let envelope_path = dir.path().join("spool/new").join(format!("{id}.json"));
	let on_disk = std::fs::read(&envelope_path).expect("read envelope bytes");
	assert!(
		on_disk.starts_with(crate::storage::MAGIC),
		"envelope must be sealed under encrypt_at_rest"
	);

	let entry = spool.load(id).expect("load");
	assert_eq!(entry.envelope.id, id);
	assert_eq!(entry.envelope.recipients, vec!["bob@example.org"]);
	assert_eq!(entry.data, sample().data);
}

/// The envelope is sealed with the message id as associated data, so a
/// bytes-for-id swap (an attacker replays the envelope of message A under
/// message B's id) is rejected by the AEAD rather than accepted as the
/// envelope for message B.
#[test]
fn envelope_bound_to_id_rejects_a_swapped_aad() {
	let dir = tempfile::tempdir().expect("tempdir");
	let crypto = MessageCrypto::for_test(&key());
	let spool = FsSpool::open_with_crypto(dir.path(), crypto.clone()).expect("open");
	let id_a = spool
		.store(&sample(), None, &BTreeMap::new())
		.expect("store a");
	let id_b = Uuid::now_v7();

	let envelope_path = dir.path().join("spool/new").join(format!("{id_a}.json"));
	let envelope_bytes = std::fs::read(&envelope_path).expect("read");
	let decode_a = crypto
		.decode_with_aad(&envelope_bytes, id_a.as_bytes())
		.expect("decode under correct id");
	let decode_b = crypto.decode_with_aad(&envelope_bytes, id_b.as_bytes());
	assert!(
		matches!(
			decode_b,
			Err(crate::storage::CryptoAuthError::AuthenticationFailed)
		),
		"swapping the id AAD must fail closed, got {:?}",
		decode_b
	);
	let parsed: Envelope = serde_json::from_slice(&decode_a).expect("parse envelope");
	assert_eq!(parsed.id, id_a);
}

/// A legacy plaintext envelope written before encryption was turned on is
/// accepted on load, and the spool rewrites it encrypted on the spot so
/// the next load goes through the AEAD. The rewrite is atomic (write to a
/// unique `tmp/<uuid>.<uuid>.json` and rename over the old one), so a crash
/// leaves the old plaintext in place and a follow-up read retries the
/// migration.
#[test]
fn legacy_plaintext_envelope_is_rewritten_encrypted_on_load() {
	let dir = tempfile::tempdir().expect("tempdir");
	// Lay down a spool with no encryption at all, so the envelope file is
	// exactly the JSON bytes (no MAGIC).
	let pre = FsSpool::open(dir.path()).expect("open pre");
	let id = pre
		.store(&sample(), None, &BTreeMap::new())
		.expect("store pre");
	let envelope_path = dir.path().join("spool/new").join(format!("{id}.json"));
	assert!(
		!std::fs::read(&envelope_path)
			.expect("read pre")
			.starts_with(crate::storage::MAGIC),
		"pre-migration envelope must be plaintext"
	);

	// Now open with encryption turned on and load the same id.
	let crypto = MessageCrypto::for_test(&key());
	let spool = FsSpool::open_with_crypto(dir.path(), crypto).expect("open crypto");
	let entry = spool.load(id).expect("load after migration");
	assert_eq!(entry.envelope.id, id);
	assert_eq!(entry.envelope.recipients, vec!["bob@example.org"]);

	// The on-disk envelope is now sealed: a reload goes through the AEAD
	// path. We can't reload via the same `spool` (the rewrite races with a
	// second read), but the byte assertion is sufficient.
	let on_disk = std::fs::read(&envelope_path).expect("read post");
	assert!(
		on_disk.starts_with(crate::storage::MAGIC),
		"after a load with crypto on, the envelope must be rewritten sealed"
	);
}

/// An operator who turns encryption off after the spool was migrated keeps
/// reading the sealed envelopes as long as a key is still loaded (the
/// `from_config` behaviour where `encrypt_at_rest = false` but
/// `encryption_key_file = ...` is still configured).
#[test]
fn turning_encryption_off_keeps_reading_already_encrypted_envelopes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let on_key = dir.path().join("mail.key");
	std::fs::write(
		&on_key,
		crate::storage::crypto::generate_key_base64().expect("keygen"),
	)
	.expect("write key");

	// First, write with encryption on.
	let enabled = Storage {
		encrypt_at_rest: true,
		encryption_key_env: None,
		encryption_key_file: Some(on_key.clone()),
		deleted_retention_days: 0,
		delivery_log_days: 0,
		blobs: None,
	};
	let on_crypto = MessageCrypto::from_config(Some(&enabled)).expect("build on");
	let spool_on = FsSpool::open_with_crypto(dir.path(), on_crypto).expect("open on");
	let id = spool_on
		.store(&sample(), None, &BTreeMap::new())
		.expect("store on");

	let envelope_path = dir.path().join("spool/new").join(format!("{id}.json"));
	assert!(
		std::fs::read(&envelope_path)
			.expect("read on")
			.starts_with(crate::storage::MAGIC)
	);

	// Now flip encryption off (the key file is still configured, so the
	// decrypt path remains available).
	let disabled = Storage {
		encrypt_at_rest: false,
		encryption_key_env: None,
		encryption_key_file: Some(on_key),
		deleted_retention_days: 0,
		delivery_log_days: 0,
		blobs: None,
	};
	let off_crypto = MessageCrypto::from_config(Some(&disabled)).expect("build off");
	let spool_off = FsSpool::open_with_crypto(dir.path(), off_crypto).expect("open off");
	assert!(!spool_off.crypto().enabled(), "encrypt_at_rest must be off");
	let entry = spool_off.load(id).expect("load off");
	assert_eq!(entry.envelope.id, id);
}

/// Flipping a byte in a sealed envelope (still on disk) makes the next load
/// fail closed: no envelope data leaks into the deliver path. The message
/// id AAD binding has not changed, so the authentication failure happens at
/// exactly the right place: the Poly1305 tag.
#[test]
fn tampered_envelope_fails_closed() {
	let dir = tempfile::tempdir().expect("tempdir");
	let crypto = MessageCrypto::for_test(&key());
	let spool = FsSpool::open_with_crypto(dir.path(), crypto).expect("open");
	let id = spool
		.store(&sample(), None, &BTreeMap::new())
		.expect("store");

	let envelope_path = dir.path().join("spool/new").join(format!("{id}.json"));
	let mut bytes = std::fs::read(&envelope_path).expect("read");
	let last = bytes.len() - 1;
	bytes[last] ^= 0x01;
	std::fs::write(&envelope_path, &bytes).expect("write tampered");

	let err = spool.load(id).expect_err("load must fail on tamper");
	let msg = err.to_string();
	assert!(
		msg.contains("authentication failed"),
		"unexpected error message: {msg}"
	);
}

/// `load_envelope` decodes the same way and also fails closed on tamper; the
/// operator CLI cannot sneak a tampered envelope past it either.
#[test]
fn load_envelope_is_also_aad_bound() {
	let dir = tempfile::tempdir().expect("tempdir");
	let crypto = MessageCrypto::for_test(&key());
	let spool = FsSpool::open_with_crypto(dir.path(), crypto).expect("open");
	let id = spool
		.store(&sample(), None, &BTreeMap::new())
		.expect("store");

	// Direct load works.
	let envelope = spool.load_envelope(id).expect("load envelope");
	assert_eq!(envelope.id, id);

	// Rewrite the envelope on disk with a different id's bytes swapped in:
	// a load must fail rather than return the wrong envelope.
	let json_a = dir.path().join("spool/new").join(format!("{id}.json"));
	let mut bytes = std::fs::read(&json_a).expect("read a");
	let other = Uuid::now_v7();
	let other_bytes = other.as_bytes();
	// The AAD is the id, but it isn't written into the envelope, only bound
	// at seal time. To prove the AAD binding we try to decode the on-disk
	// bytes under the wrong id through the crypto directly.
	let crypto = MessageCrypto::for_test(&key());
	let resealed = std::fs::read(&json_a).expect("read a again");
	let wrong = crypto.decode_with_aad(&resealed, other_bytes);
	assert!(
		matches!(
			wrong,
			Err(crate::storage::CryptoAuthError::AuthenticationFailed)
		),
		"a wrong-id decode must not succeed"
	);

	// And a trivial tamper still fails.
	let last = bytes.len() - 1;
	bytes[last] ^= 0x01;
	std::fs::write(&json_a, &bytes).expect("tamper");
	let err = spool.load_envelope(id).expect_err("tamper fails");
	assert!(err.to_string().contains("authentication failed"));
}

/// An edit (a delivery attempt being recorded, an operator hold) on an
/// envelope still in the legacy plaintext form must finish: the edit holds
/// the spool lock, so it must not wait on that same lock to migrate the
/// envelope it is about to rewrite sealed anyway.
#[test]
fn editing_a_legacy_plaintext_envelope_under_encryption_completes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let id = FsSpool::open(dir.path())
		.expect("open pre")
		.store(&sample(), None, &BTreeMap::new())
		.expect("store pre");
	let crypto = MessageCrypto::for_test(&crate::test_fixtures::bytes::<32>());
	let spool = FsSpool::open_with_crypto(dir.path(), crypto).expect("open crypto");

	let (done, finished) = std::sync::mpsc::channel();
	std::thread::spawn(move || {
		let attempts = spool
			.update_envelope(id, |envelope| envelope.attempts += 1)
			.map(|envelope| envelope.attempts)
			.map_err(|error| error.kind());
		let _ = done.send(attempts);
	});
	let outcome = finished.recv_timeout(std::time::Duration::from_secs(10));
	assert_eq!(
		outcome,
		Ok(Ok(1)),
		"the edit must finish instead of waiting on its own lock"
	);
	let envelope_path = dir.path().join("spool/new").join(format!("{id}.json"));
	assert!(
		std::fs::read(&envelope_path)
			.expect("read post")
			.starts_with(crate::storage::MAGIC),
		"the edited envelope must be written sealed"
	);
}
