//! Unit tests for the at-rest message-encryption envelope.

use super::*;
use crate::config::Storage;

fn test_key() -> [u8; KEY_LEN] {
	[7u8; KEY_LEN]
}

#[test]
fn roundtrip_encrypts_and_decrypts() {
	let crypto = MessageCrypto::for_test(&test_key());
	let plaintext = b"Subject: secret\r\n\r\nthe body\r\n";
	let stored = crypto.encode(plaintext).expect("encode");
	// On disk it is the envelope, never the plaintext.
	assert!(stored.starts_with(MAGIC));
	assert_ne!(stored, plaintext);
	assert!(!stored.windows(6).any(|w| w == b"secret"));
	// Length is exactly the fixed overhead over the plaintext.
	assert_eq!(stored.len(), plaintext.len() + OVERHEAD);
	let back = crypto.decode(&stored).expect("decode");
	assert_eq!(back, plaintext);
}

#[test]
fn nonce_is_fresh_per_write() {
	let crypto = MessageCrypto::for_test(&test_key());
	let a = crypto.encode(b"same").expect("encode a");
	let b = crypto.encode(b"same").expect("encode b");
	// Identical plaintext must not produce identical ciphertext (random nonce).
	assert_ne!(a, b);
	assert_eq!(crypto.decode(&a).expect("a"), b"same");
	assert_eq!(crypto.decode(&b).expect("b"), b"same");
}

#[test]
fn disabled_passes_plaintext_through() {
	let crypto = MessageCrypto::disabled();
	let plaintext = b"hello";
	assert_eq!(crypto.encode(plaintext).expect("encode"), plaintext);
	assert_eq!(crypto.decode(plaintext).expect("decode"), plaintext);
}

#[test]
fn decode_of_legacy_plaintext_is_unchanged_even_when_enabled() {
	// An encryption-enabled crypto must still read pre-existing plaintext files
	// (no MAGIC) verbatim, so a store migrates in place with no flag-day.
	let crypto = MessageCrypto::for_test(&test_key());
	let legacy = b"Subject: old\r\n\r\nplaintext on disk\r\n";
	assert_eq!(crypto.decode(legacy).expect("decode"), legacy);
}

#[test]
fn decode_fails_closed_when_tampered() {
	let crypto = MessageCrypto::for_test(&test_key());
	let mut stored = crypto.encode(b"authentic").expect("encode");
	// Flip a ciphertext byte: authentication must fail, never return garbage.
	let last = stored.len() - 1;
	stored[last] ^= 0x01;
	assert!(crypto.decode(&stored).is_err());
}

#[test]
fn decode_fails_closed_when_encrypted_but_no_key() {
	let with_key = MessageCrypto::for_test(&test_key());
	let stored = with_key.encode(b"secret").expect("encode");
	// A crypto with no key must refuse an encrypted file rather than hand back
	// ciphertext as if it were plaintext.
	let no_key = MessageCrypto::disabled();
	assert!(no_key.decode(&stored).is_err());
}

#[test]
fn decode_rejects_truncated_envelope() {
	let crypto = MessageCrypto::for_test(&test_key());
	let mut stored = MAGIC.to_vec();
	stored.extend_from_slice(&[0u8; 4]); // shorter than a nonce
	assert!(crypto.decode(&stored).is_err());
}

#[test]
fn from_config_none_is_disabled() {
	let crypto = MessageCrypto::from_config(None).expect("build");
	assert!(!crypto.enabled());
	assert_eq!(crypto.encode(b"x").expect("encode"), b"x");
}

#[test]
fn from_config_enabled_without_key_fails_closed() {
	let storage = Storage {
		encrypt_at_rest: true,
		encryption_key_env: None,
		encryption_key_file: None,
	};
	let result = MessageCrypto::from_config(Some(&storage));
	assert!(matches!(result, Err(CryptoError::NoKeySource)));
}

#[test]
fn from_config_loads_key_from_file() {
	let dir = tempfile::tempdir().expect("tempdir");
	let key_path = dir.path().join("mail.key");
	let key_b64 = generate_key_base64().expect("keygen");
	std::fs::write(&key_path, &key_b64).expect("write key");
	let storage = Storage {
		encrypt_at_rest: true,
		encryption_key_env: None,
		encryption_key_file: Some(key_path),
	};
	let crypto = MessageCrypto::from_config(Some(&storage)).expect("build");
	assert!(crypto.enabled());
	let stored = crypto.encode(b"hi").expect("encode");
	assert!(stored.starts_with(MAGIC));
	assert_eq!(crypto.decode(&stored).expect("decode"), b"hi");
}

#[test]
fn from_config_keeps_key_loaded_when_disabled() {
	// Encryption off but a key present: new writes are plaintext, yet already
	// encrypted files still decode.
	let dir = tempfile::tempdir().expect("tempdir");
	let key_path = dir.path().join("mail.key");
	std::fs::write(&key_path, generate_key_base64().expect("keygen")).expect("write");
	let enabled = Storage {
		encrypt_at_rest: true,
		encryption_key_env: None,
		encryption_key_file: Some(key_path.clone()),
	};
	let ciphertext = MessageCrypto::from_config(Some(&enabled))
		.expect("build enabled")
		.encode(b"kept")
		.expect("encode");

	let disabled = Storage {
		encrypt_at_rest: false,
		encryption_key_env: None,
		encryption_key_file: Some(key_path),
	};
	let crypto = MessageCrypto::from_config(Some(&disabled)).expect("build disabled");
	assert!(!crypto.enabled());
	// A new write is plaintext.
	assert_eq!(crypto.encode(b"new").expect("encode"), b"new");
	// But the earlier ciphertext still decodes.
	assert_eq!(crypto.decode(&ciphertext).expect("decode"), b"kept");
}

#[test]
fn from_config_rejects_malformed_key() {
	let dir = tempfile::tempdir().expect("tempdir");
	let key_path = dir.path().join("bad.key");
	std::fs::write(&key_path, "not-base64-32-bytes").expect("write");
	let storage = Storage {
		encrypt_at_rest: true,
		encryption_key_env: None,
		encryption_key_file: Some(key_path),
	};
	assert!(matches!(
		MessageCrypto::from_config(Some(&storage)),
		Err(CryptoError::KeyMalformed)
	));
}

#[test]
fn generate_key_is_valid_length() {
	let key = generate_key_base64().expect("keygen");
	let bytes = base64::engine::general_purpose::STANDARD
		.decode(&key)
		.expect("base64");
	assert_eq!(bytes.len(), KEY_LEN);
}

#[test]
fn stored_plaintext_len_accounts_for_overhead() {
	let dir = tempfile::tempdir().expect("tempdir");
	let crypto = MessageCrypto::for_test(&test_key());
	let plaintext = b"Subject: sized\r\n\r\nbody bytes here\r\n";
	let stored = crypto.encode(plaintext).expect("encode");
	let path = dir.path().join("msg.eml");
	std::fs::write(&path, &stored).expect("write");
	let len = crypto.stored_plaintext_len(&path, stored.len() as u64);
	assert_eq!(len, plaintext.len() as u64);
}

#[test]
fn stored_plaintext_len_passes_through_plaintext_file() {
	let dir = tempfile::tempdir().expect("tempdir");
	let crypto = MessageCrypto::for_test(&test_key());
	let plaintext = b"legacy on disk, no magic";
	let path = dir.path().join("legacy.eml");
	std::fs::write(&path, plaintext).expect("write");
	let len = crypto.stored_plaintext_len(&path, plaintext.len() as u64);
	assert_eq!(len, plaintext.len() as u64);
}
