//! SASL PLAIN credential parsing and verification (RFC 4616).

pub mod cost;

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
	hash_password_with_cost(password, cost::current(), &fresh_salt()?)
}

/// A salt straight out of the system generator. It is produced whole: there
/// is no placeholder array that is later overwritten, so no fixed value can
/// reach a hash if the generator fails.
fn fresh_salt() -> Result<[u8; 16], String> {
	Ok(
		ring::rand::generate::<[u8; 16]>(&ring::rand::SystemRandom::new())
			.map_err(|_| "cannot gather salt entropy".to_string())?
			.expose(),
	)
}

/// A new hash of `password`, which just verified against `stored`, when
/// `stored` is weaker than the cost in force (see [`cost::rewrite_cost`]):
/// a fresh salt, and for each parameter the larger of the stored and the
/// configured value. `None` when `stored` needs no rewrite.
pub(crate) fn upgraded_hash(stored: &str, password: &str) -> Option<Result<String, String>> {
	let cost = cost::rewrite_cost(stored, cost::current())?;
	Some(fresh_salt().and_then(|salt| hash_password_with_cost(password, cost, &salt)))
}

/// [`hash_password`] at an explicit `cost` and `salt`, which the caller draws.
pub(crate) fn hash_password_with_cost(
	password: &str,
	cost: cost::Argon2Cost,
	salt: &[u8; 16],
) -> Result<String, String> {
	use argon2::password_hash::PasswordHasher;
	cost.hasher()?
		.hash_password_with_salt(password.as_bytes(), salt)
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
pub(crate) mod tests;
