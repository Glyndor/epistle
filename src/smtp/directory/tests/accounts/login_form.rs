//! Login compares the candidate against the stored hash and nothing else.
//! The length and character rules apply when a password is set; a stored
//! hash can predate them (written into the config by hand, set by an older
//! release, or set while the Unicode policy was on), and refusing those at
//! login would lock the account out.

use super::*;
use crate::password::{MIN_LENGTH, Policy};
use crate::smtp::auth::tests::base::hash;
use crate::test_fixtures as fixtures;

fn directory_with(password: &str, policy: Policy) -> Directory {
	Directory::new(
		["example.org".to_string()],
		[("alice@example.org".to_string(), "alice".to_string())],
	)
	.with_password_hashes([("alice".to_string(), hash(password))])
	.with_password_policy(policy)
}

#[test]
fn a_hash_of_a_password_shorter_than_the_rule_still_logs_in() {
	let short = fixtures::printable_ascii(MIN_LENGTH - 4);
	let directory = directory_with(&short, Policy::ASCII_ONLY);
	assert_eq!(
		directory.authenticate("alice", &short, crate::config::Protocol::Imap),
		Some("alice".to_string())
	);
	assert_eq!(
		directory.authenticate("alice", &format!("{short}x"), crate::config::Protocol::Imap),
		None,
		"a wrong password must still fail"
	);
}

#[test]
fn a_unicode_password_still_logs_in_after_the_policy_goes_back_to_ascii() {
	let password = format!("contrase\u{00F1}a{}", fixtures::printable_ascii(MIN_LENGTH));
	let directory = directory_with(&password, Policy::ASCII_ONLY);
	assert_eq!(
		directory.authenticate("alice", &password, crate::config::Protocol::Imap),
		Some("alice".to_string())
	);
}

#[test]
fn the_unicode_policy_logs_in_from_another_decomposition() {
	let tail = fixtures::printable_ascii(MIN_LENGTH);
	let composed = format!("contrase\u{00F1}a{tail}");
	let decomposed = format!("contrase\u{006E}\u{0303}a{tail}");
	let directory = directory_with(&composed, Policy::unicode());
	assert_eq!(
		directory.authenticate("alice", &decomposed, crate::config::Protocol::Imap),
		Some("alice".to_string())
	);
}
