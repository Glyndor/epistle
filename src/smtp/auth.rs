//! SASL PLAIN credential parsing and verification (RFC 4616).

use argon2::Argon2;
use argon2::password_hash::PasswordVerifier;
use argon2::password_hash::phc::PasswordHash;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

/// Parsed PLAIN credentials.
#[derive(Debug, PartialEq, Eq)]
pub struct PlainCredentials {
	/// Authentication identity (the user being authenticated). RFC 4616
	/// permits an authorization identity too, but the parser rejects any
	/// mismatch as impersonation.
	pub authcid: String,
	/// The password in plaintext (the SASL PLAIN message is base64, not
	/// hashed). Stored only as long as the caller needs it.
	pub password: String,
}

/// Why a PLAIN exchange was rejected before verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlainError {
	/// Not valid base64.
	BadEncoding,
	/// Decoded message is not `authzid NUL authcid NUL passwd`.
	BadFormat,
	/// An authorization identity different from the authentication
	/// identity was requested; impersonation is not supported.
	AuthzidMismatch,
}

/// Decode the base64 SASL PLAIN message.
pub fn parse_plain(encoded: &str) -> Result<PlainCredentials, PlainError> {
	let decoded = BASE64
		.decode(encoded.trim())
		.map_err(|_| PlainError::BadEncoding)?;
	let text = String::from_utf8(decoded).map_err(|_| PlainError::BadFormat)?;
	let mut parts = text.split('\0');
	let (Some(authzid), Some(authcid), Some(password), None) =
		(parts.next(), parts.next(), parts.next(), parts.next())
	else {
		return Err(PlainError::BadFormat);
	};
	if authcid.is_empty() || password.is_empty() {
		return Err(PlainError::BadFormat);
	}
	if !authzid.is_empty() && authzid != authcid {
		return Err(PlainError::AuthzidMismatch);
	}
	Ok(PlainCredentials {
		authcid: authcid.to_string(),
		password: password.to_string(),
	})
}

/// Hash a password with argon2id for storage (PHC string).
pub fn hash_password(password: &str) -> Result<String, String> {
	use argon2::password_hash::PasswordHasher;
	use ring::rand::{SecureRandom, SystemRandom};

	let mut salt = [0u8; 16];
	SystemRandom::new()
		.fill(&mut salt)
		.map_err(|_| "cannot gather salt entropy".to_string())?;
	Argon2::default()
		.hash_password_with_salt(password.as_bytes(), &salt)
		.map(|hash| hash.to_string())
		.map_err(|error| error.to_string())
}

/// Verify a password against an argon2id PHC hash. Any malformed hash or
/// mismatch is a plain `false`: callers must not learn why.
pub fn verify_password(phc_hash: &str, password: &str) -> bool {
	let Ok(parsed) = PasswordHash::new(phc_hash) else {
		return false;
	};
	Argon2::default()
		.verify_password(password.as_bytes(), &parsed)
		.is_ok()
}

#[cfg(test)]
pub(crate) mod tests {
	use super::*;
	use crate::test_fixtures as fixtures;

	pub(crate) fn hash(password: &str) -> String {
		super::hash_password(password).expect("fixture password hash")
	}

	pub(crate) use fixtures::password as fixture_password;
	pub(crate) use fixtures::second_password;
	pub(crate) use fixtures::wrong_password;

	fn encode(authzid: &str, authcid: &str, password: &str) -> String {
		BASE64.encode(format!("{authzid}\0{authcid}\0{password}"))
	}

	#[test]
	fn parses_plain_without_authzid() {
		let parsed = parse_plain(&encode("", "alice", fixture_password())).expect("valid");
		assert_eq!(parsed.authcid, "alice");
		assert!(
			parsed.password == fixture_password(),
			"PLAIN password must match"
		);
	}

	#[test]
	fn parses_plain_with_matching_authzid() {
		assert!(parse_plain(&encode("alice", "alice", fixture_password())).is_ok());
	}

	#[test]
	fn rejects_foreign_authzid() {
		assert!(
			(parse_plain(&encode("root", "alice", fixture_password())))
				== (Err(PlainError::AuthzidMismatch)),
			"credential field must match"
		);
	}

	#[test]
	fn rejects_bad_base64() {
		assert!(
			(parse_plain("!!not-base64!!")) == (Err(PlainError::BadEncoding)),
			"credential field must match"
		);
	}

	#[test]
	fn rejects_wrong_field_count() {
		assert!(
			(parse_plain(&BASE64.encode("only-one-field"))) == (Err(PlainError::BadFormat)),
			"credential field must match"
		);
		assert!(
			(parse_plain(&BASE64.encode("a\0b\0c\0d"))) == (Err(PlainError::BadFormat)),
			"credential field must match"
		);
	}

	#[test]
	fn rejects_empty_identity_or_password() {
		assert!(
			(parse_plain(&encode("", "", fixture_password()))) == (Err(PlainError::BadFormat)),
			"credential field must match"
		);
		assert!(
			(parse_plain(&encode("", "alice", ""))) == (Err(PlainError::BadFormat)),
			"credential field must match"
		);
	}

	#[test]
	fn runtime_hash_roundtrips() {
		let hash = hash_password(fixture_password()).expect("hashes");
		assert!(hash.starts_with("$argon2id$"));
		assert!(verify_password(&hash, fixture_password()));
		assert!(!verify_password(&hash, wrong_password()));
	}

	#[test]
	fn verifies_correct_password() {
		let phc = hash(fixture_password());
		assert!(verify_password(&phc, fixture_password()));
	}

	#[test]
	fn rejects_wrong_password() {
		let phc = hash(fixture_password());
		assert!(!verify_password(&phc, wrong_password()));
	}

	#[test]
	fn rejects_malformed_hash() {
		assert!(!verify_password("not-a-phc-string", fixture_password()));
	}
}

#[cfg(test)]
#[path = "auth_tests_fixtures.rs"]
mod fixture_tests;
