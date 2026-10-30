use super::*;
use crate::migrate::import::tests::test_keys;

#[test]
fn ed25519_version_2_is_kept_as_is() {
	let pem = test_keys::ed25519_v2_pem();
	let key = normalize(&pem, Some(Algorithm::Ed25519)).expect("key");
	assert_eq!(key.algorithm, Algorithm::Ed25519);
	assert_eq!(to_pem(&key.pkcs8).as_str(), pem);
}

#[test]
fn ed25519_version_1_gains_its_public_key() {
	let (pem, v2) = test_keys::ed25519_v1();
	let key = normalize(&pem, None).expect("key");
	assert_eq!(key.algorithm, Algorithm::Ed25519);
	assert_eq!(*key.pkcs8, v2, "the same key, in the form ring writes");
	assert!(Ed25519KeyPair::from_pkcs8(&key.pkcs8).is_ok());
}

#[test]
fn rsa_pkcs1_is_wrapped_into_the_same_pkcs8() {
	let pkcs8 = normalize(test_keys::rsa_pkcs8_pem(), Some(Algorithm::Rsa)).expect("pkcs8");
	assert_eq!(*pkcs8.pkcs8, test_keys::rsa_pkcs8_der());
	let pkcs1 = normalize(&test_keys::rsa_pkcs1_pem(), Some(Algorithm::Rsa)).expect("pkcs1");
	assert_eq!(*pkcs1.pkcs8, test_keys::rsa_pkcs8_der());
}

#[test]
fn unusable_keys_are_refused_with_a_reason_and_no_key() {
	assert_eq!(normalize("no pem here", None).err(), Some(KeyError::NotPem));
	let encrypted =
		"-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n";
	assert_eq!(normalize(encrypted, None).err(), Some(KeyError::Encrypted));
	let legacy = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nAAAA\n-----END RSA PRIVATE KEY-----\n";
	assert_eq!(normalize(legacy, None).err(), Some(KeyError::Encrypted));
	let junk = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";
	assert_eq!(normalize(junk, None).err(), Some(KeyError::Unsupported));
	assert_eq!(
		normalize(&test_keys::ed25519_v2_pem(), Some(Algorithm::Rsa)).err(),
		Some(KeyError::WrongAlgorithm)
	);
	let huge = "x".repeat(MAX_KEY_BYTES + 1);
	assert_eq!(normalize(&huge, None).err(), Some(KeyError::NotPem));
}

#[test]
fn selectors_are_dns_labels() {
	for good in ["2024a", "mail-1", "s1.example"] {
		assert!(valid_selector(good), "{good}");
	}
	for bad in ["", "../x", "a/b", "a..b", "sel_1", &"a".repeat(64)] {
		assert!(!valid_selector(bad), "{bad}");
	}
}
