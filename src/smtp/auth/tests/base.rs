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
	let tail = crate::test_fixtures::printable_ascii(crate::password::MIN_LENGTH);
	let nfc = format!("contrase\u{00F1}a{tail}");
	let nfd = format!("contrase\u{006E}\u{0303}a{tail}");
	assert_ne!(
		nfc, nfd,
		"shape precondition: the two forms differ in bytes"
	);
	let prepared_nfc = policy.prepare(&nfc).expect("nfc is valid");
	let prepared_nfd = policy.prepare(&nfd).expect("nfd is valid");
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
	let phc_from_nfd = super::hash_password(prepared_nfd.as_ref()).expect("hashes under unicode");
	assert!(verify_password(&phc_from_nfd, prepared_nfc.as_ref()));
	assert!(verify_password(&phc_from_nfd, prepared_nfd.as_ref()));
	// A wrong password still fails, even after the policy prepare.
	let wrong = crate::test_fixtures::printable_ascii(crate::password::MIN_LENGTH + 2);
	assert!(!verify_password(&phc, &wrong));
}
