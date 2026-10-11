use std::path::Path;

use super::{Pseudonymizer, account};

fn is_pseudonym(text: &str) -> bool {
	text.strip_prefix("acct-").is_some_and(|rest| {
		rest.len() == 12
			&& rest
				.chars()
				.all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
	})
}

#[test]
fn pseudonym_has_the_documented_shape() {
	let pseudonymizer = Pseudonymizer::with_key([7u8; 32]);
	let id = pseudonymizer.account("alice");
	assert!(is_pseudonym(&id), "pseudonym does not match acct-<12 hex>");
	assert!(!id.contains("alice"), "pseudonym must not contain the name");
}

#[test]
fn pseudonym_is_stable_for_a_name_and_differs_between_names() {
	let pseudonymizer = Pseudonymizer::with_key([7u8; 32]);
	assert_eq!(
		pseudonymizer.account("alice"),
		pseudonymizer.account("alice")
	);
	assert_ne!(pseudonymizer.account("alice"), pseudonymizer.account("bob"));
}

#[test]
fn pseudonym_differs_between_keys() {
	let first = Pseudonymizer::with_key([1u8; 32]);
	let second = Pseudonymizer::with_key([2u8; 32]);
	assert_ne!(first.account("alice"), second.account("alice"));
}

#[test]
fn pseudonym_matches_an_independent_hmac() {
	let key = [9u8; 32];
	let tag = ring::hmac::sign(
		&ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key),
		b"alice",
	);
	let expected: String = tag.as_ref()[..6]
		.iter()
		.map(|b| format!("{b:02x}"))
		.collect();
	assert_eq!(
		Pseudonymizer::with_key(key).account("alice"),
		format!("acct-{expected}")
	);
}

#[test]
fn open_creates_an_owner_only_key_and_reuses_it() {
	let dir = tempfile::tempdir().expect("tempdir");
	let first = Pseudonymizer::open(dir.path()).expect("create key");
	let key_path = dir.path().join("log-pseudonym.key");
	assert_eq!(std::fs::read(&key_path).expect("key file").len(), 32);
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		let mode = std::fs::metadata(&key_path)
			.expect("stat")
			.permissions()
			.mode();
		assert_eq!(mode & 0o777, 0o600, "key file must be owner-only");
	}
	let second = Pseudonymizer::open(dir.path()).expect("reload key");
	assert_eq!(first.account("alice"), second.account("alice"));
	let other = tempfile::tempdir().expect("tempdir");
	let elsewhere = Pseudonymizer::open(other.path()).expect("second key");
	assert_ne!(first.account("alice"), elsewhere.account("alice"));
}

#[test]
fn path_replaces_only_the_account_component() {
	let pseudonymizer = Pseudonymizer::with_key([7u8; 32]);
	let id = pseudonymizer.account("alice");
	let shown = pseudonymizer.path(Path::new("/var/lib/epistle/accounts/alice/new/x.eml"));
	assert_eq!(shown, format!("/var/lib/epistle/accounts/{id}/new/x.eml"));
	let unrelated = pseudonymizer.path(Path::new("/var/lib/epistle/queue/x.eml"));
	assert_eq!(unrelated, "/var/lib/epistle/queue/x.eml");
}

#[test]
fn process_pseudonym_is_stable_and_hides_the_name() {
	let id = account("carol");
	assert_eq!(id, account("carol"));
	assert!(
		is_pseudonym(&id),
		"process pseudonym does not match acct-<12 hex>"
	);
}
