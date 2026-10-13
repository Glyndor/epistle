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
///
/// The password is hashed *as given*: callers must apply whatever NFKC
/// normalisation the password policy calls for before calling this (with
/// the ASCII-only policy the input is already on canonical form, so a
/// pass-through is correct; with the Unicode policy the caller must run
/// `Policy::unicode().prepare(password)` first). Keeping the function pure
/// — no policy parameter — means the bytes hashed and verified are
/// always the same, and the policy decision lives at one place per call
/// site.
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

/// Verify a password against an argon2id PHC hash. The password must
/// arrive already prepared (NFKC-normalised under the unicode password
/// policy, raw bytes under the ASCII-only policy); the function does no
/// preparation of its own, so the byte stream hashed at set-time and the
/// byte stream verified at login-time always agree. Any malformed hash
/// or mismatch is a plain `false`: callers must not learn why.
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
	use crate::password::Policy;
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
		// The wire message for an empty password is `\0alice\0`: both NULs
		// present, nothing after the second.
		assert!(
			(parse_plain(&BASE64.encode("\0alice\0"))) == (Err(PlainError::BadFormat)),
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

	#[test]
	fn unicode_policy_normalises_before_hashing_and_verifying() {
		// The crypto functions stay pure: they hash and verify whatever
		// bytes arrive. The preparation step is the policy's job. Calling
		// `Policy::unicode().prepare(...)` on both set and verify is what
		// makes a password typed in one keyboard composition verify from
		// another, and the contract here is that the same `Cow<str>` flowed
		// in on both paths.
		let policy = Policy::unicode();
		let nfc = "contrase\u{00F1}aSegura12";
		let nfd = "contrase\u{006E}\u{0303}aSegura12";
		assert_ne!(
			nfc, nfd,
			"shape precondition: the two forms differ in bytes"
		);
		let prepared_nfc = policy.prepare(nfc).expect("nfc is valid");
		let prepared_nfd = policy.prepare(nfd).expect("nfd is valid");
		assert_eq!(
			prepared_nfc.as_ref(),
			prepared_nfd.as_ref(),
			"shape precondition: NFKC collapses NFD to NFC",
		);
		// Set under NFC…
		let phc = super::hash_password(prepared_nfc.as_ref()).expect("hashes under unicode");
		// … verifies against any decomposition as long as the candidate
		// goes through the same prepare call.
		assert!(verify_password(&phc, prepared_nfc.as_ref()));
		assert!(verify_password(&phc, prepared_nfd.as_ref()));
		// And the reverse: set with NFD-derived bytes, verify with the
		// NFD bytes or the NFC bytes — both prepare to the same form, so
		// both verify.
		let phc_from_nfd =
			super::hash_password(prepared_nfd.as_ref()).expect("hashes under unicode");
		assert!(verify_password(&phc_from_nfd, prepared_nfc.as_ref()));
		assert!(verify_password(&phc_from_nfd, prepared_nfd.as_ref()));
		// A wrong password still fails, even after the policy prepare.
		assert!(!verify_password(&phc, "wrongPassword12"));
	}
}

#[cfg(test)]
#[path = "auth_tests_fixtures.rs"]
mod fixture_tests;
