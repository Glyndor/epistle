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
	use std::sync::LazyLock;

	use argon2::password_hash::PasswordHasher;
	use uuid::Uuid;

	use super::*;

	pub(crate) fn hash(password: &str) -> String {
		// Test-time hashing; runtime only ever verifies.
		Argon2::default()
			.hash_password_with_salt(password.as_bytes(), b"0123456789abcdef")
			.expect("hash")
			.to_string()
	}

	/// The password every SMTP fixture hashes and later presents, minted
	/// once per test binary. A literal in its place reaches [`hash`] and the
	/// session harness's `plain` through a parameter named `password`, which
	/// is the dataflow `rust/hard-coded-cryptographic-value` reports; the API
	/// tests moved their bearer token to this shape in #725. No test depends
	/// on the value: each hashes it, presents it, and reads the outcome.
	pub(crate) fn fixture_password() -> &'static str {
		static PASSWORD: LazyLock<String> = LazyLock::new(|| Uuid::now_v7().simple().to_string());
		PASSWORD.as_str()
	}

	/// A password that is not [`fixture_password`], for the tests that
	/// present the wrong one. Minted the same way, so it is never a literal
	/// and cannot collide with the right one by accident.
	pub(crate) fn wrong_password() -> &'static str {
		static PASSWORD: LazyLock<String> = LazyLock::new(|| Uuid::now_v7().simple().to_string());
		PASSWORD.as_str()
	}

	fn encode(authzid: &str, authcid: &str, password: &str) -> String {
		BASE64.encode(format!("{authzid}\0{authcid}\0{password}"))
	}

	#[test]
	fn parses_plain_without_authzid() {
		let parsed = parse_plain(&encode("", "alice", "secret")).expect("valid");
		assert_eq!(parsed.authcid, "alice");
		assert_eq!(parsed.password, "secret");
	}

	#[test]
	fn parses_plain_with_matching_authzid() {
		assert!(parse_plain(&encode("alice", "alice", "secret")).is_ok());
	}

	#[test]
	fn rejects_foreign_authzid() {
		assert_eq!(
			parse_plain(&encode("root", "alice", "secret")),
			Err(PlainError::AuthzidMismatch)
		);
	}

	#[test]
	fn rejects_bad_base64() {
		assert_eq!(parse_plain("!!not-base64!!"), Err(PlainError::BadEncoding));
	}

	#[test]
	fn rejects_wrong_field_count() {
		assert_eq!(
			parse_plain(&BASE64.encode("only-one-field")),
			Err(PlainError::BadFormat)
		);
		assert_eq!(
			parse_plain(&BASE64.encode("a\0b\0c\0d")),
			Err(PlainError::BadFormat)
		);
	}

	#[test]
	fn rejects_empty_identity_or_password() {
		assert_eq!(
			parse_plain(&encode("", "", "secret")),
			Err(PlainError::BadFormat)
		);
		assert_eq!(
			parse_plain(&encode("", "alice", "")),
			Err(PlainError::BadFormat)
		);
	}

	#[test]
	fn fixed_salt_hash_matches_the_string_argon2_0_5_wrote() {
		// Computed with argon2 0.5.3 for this salt and password before the
		// crate moved to 0.6, which changed how the salt is handed over
		// (raw bytes instead of a B64 string). Stored hashes must keep
		// verifying, and the PHC encoding must not drift under a bump.
		let stored = "$argon2id$v=19$m=19456,t=2,p=1$MDEyMzQ1Njc4OWFiY2RlZg$8qPpaWig0H31wvibKAgpght2Ry2M8rtRQYtZ93ooMus";
		assert_eq!(hash("secret"), stored);
		assert!(verify_password(stored, "secret"));
	}

	#[test]
	fn runtime_hash_roundtrips() {
		let hash = hash_password("hunter2").expect("hashes");
		assert!(hash.starts_with("$argon2id$"));
		assert!(verify_password(&hash, "hunter2"));
		assert!(!verify_password(&hash, "hunter3"));
	}

	#[test]
	fn verifies_correct_password() {
		let phc = hash("secret");
		assert!(verify_password(&phc, "secret"));
	}

	#[test]
	fn rejects_wrong_password() {
		let phc = hash("secret");
		assert!(!verify_password(&phc, "not-secret"));
	}

	#[test]
	fn rejects_malformed_hash() {
		assert!(!verify_password("not-a-phc-string", "secret"));
	}
}
