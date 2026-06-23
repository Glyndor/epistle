//! Tests for recipient resolution and the directory.

use super::*;

fn directory() -> Directory {
	Directory::new(
		["example.org".to_string()],
		[
			("Alice@EXAMPLE.org".to_string(), "alice".to_string()),
			("bob@example.org".to_string(), "bob".to_string()),
		],
	)
}

fn parse(raw: &str) -> Address {
	Address::parse(raw).expect("valid address")
}

#[test]
fn quota_resolves_account_then_domain_then_none() {
	let directory = directory()
		.with_account_quotas([("alice".to_string(), 1000)])
		.with_domain_quotas([("example.org".to_string(), 500)]);
	// Account quota wins.
	assert_eq!(directory.quota_for("alice"), Some(1000));
	// bob has no account quota -> the domain default applies.
	assert_eq!(directory.quota_for("bob"), Some(500));
	// Case-insensitive on the account name.
	assert_eq!(directory.quota_for("ALICE"), Some(1000));
	// An unknown account with no hosted address -> no quota.
	assert_eq!(directory.quota_for("nobody"), None);
}

#[test]
fn quota_is_none_without_any_configured() {
	assert_eq!(directory().quota_for("alice"), None);
}

fn aliased() -> Directory {
	directory().with_aliases([(
		"team@example.org".to_string(),
		AliasSpec {
			members: vec![
				"alice@example.org".to_string(),
				"bob@example.org".to_string(),
			],
			senders: Vec::new(),
			hidden: true,
			list_id: None,
		},
	)])
}

#[test]
fn alias_resolves_to_all_member_accounts() {
	let dir = aliased();
	match dir.resolve(&parse("team@example.org")) {
		Resolution::Alias(accounts) => {
			assert!(accounts.contains(&"alice".to_string()));
			assert!(accounts.contains(&"bob".to_string()));
			assert_eq!(accounts.len(), 2);
		}
		other => panic!("expected alias, got {other:?}"),
	}
}

#[test]
fn alias_sender_restriction() {
	// No explicit senders: any member may send as the alias; a non-member may not.
	let dir = aliased();
	assert!(dir.owns_address("alice", &parse("team@example.org")));
	assert!(dir.owns_address("bob", &parse("team@example.org")));
	assert!(!dir.owns_address("carol", &parse("team@example.org")));

	// Explicit senders restrict to a subset.
	let restricted = directory().with_aliases([(
		"team@example.org".to_string(),
		AliasSpec {
			members: vec![
				"alice@example.org".to_string(),
				"bob@example.org".to_string(),
			],
			senders: vec!["alice@example.org".to_string()],
			hidden: true,
			list_id: None,
		},
	)]);
	assert!(restricted.owns_address("alice", &parse("team@example.org")));
	assert!(!restricted.owns_address("bob", &parse("team@example.org")));
}

#[test]
fn alias_membership_visibility() {
	// Hidden (default): membership is not disclosed.
	assert_eq!(aliased().alias_members("team@example.org"), None);
	// Visible: membership is returned.
	let visible = directory().with_aliases([(
		"team@example.org".to_string(),
		AliasSpec {
			members: vec!["alice@example.org".to_string()],
			senders: Vec::new(),
			hidden: false,
			list_id: None,
		},
	)]);
	assert_eq!(
		visible.alias_members("team@example.org"),
		Some(vec!["alice@example.org".to_string()])
	);
	// A non-alias address is never a member list.
	assert_eq!(aliased().alias_members("alice@example.org"), None);
}

#[test]
fn resolves_known_address_case_insensitively() {
	assert_eq!(
		directory().resolve(&parse("ALICE@example.ORG")),
		Resolution::Account("alice".to_string())
	);
}

#[test]
fn unknown_user_in_local_domain() {
	assert_eq!(
		directory().resolve(&parse("carol@example.org")),
		Resolution::UnknownUser
	);
}

#[test]
fn foreign_domain_is_not_local() {
	assert_eq!(
		directory().resolve(&parse("alice@elsewhere.example")),
		Resolution::NotLocal
	);
}

#[test]
fn empty_directory_resolves_nothing() {
	let empty = Directory::default();
	assert_eq!(
		empty.resolve(&parse("alice@example.org")),
		Resolution::NotLocal
	);
}

#[test]
fn subaddressing_resolves_to_base_account() {
	// bob+anything@example.org delivers to bob.
	assert_eq!(
		directory().resolve(&parse("bob+newsletter@example.org")),
		Resolution::Account("bob".to_string())
	);
	// Only the first separator matters; the rest is part of the tag.
	assert_eq!(
		directory().resolve(&parse("Bob+a+b@EXAMPLE.org")),
		Resolution::Account("bob".to_string())
	);
}

#[test]
fn subaddressing_with_unknown_base_is_unknown_user() {
	assert_eq!(
		directory().resolve(&parse("carol+tag@example.org")),
		Resolution::UnknownUser
	);
}

#[test]
fn leading_separator_is_not_a_subaddress() {
	assert_eq!(
		directory().resolve(&parse("+tag@example.org")),
		Resolution::UnknownUser
	);
}

#[test]
fn subaddressing_can_be_disabled() {
	let directory = directory().with_subaddress_separators([]);
	assert_eq!(
		directory.resolve(&parse("bob+tag@example.org")),
		Resolution::UnknownUser
	);
}

#[test]
fn subaddress_separators_are_configurable() {
	let directory = directory().with_subaddress_separators(['-']);
	assert_eq!(
		directory.resolve(&parse("bob-tag@example.org")),
		Resolution::Account("bob".to_string())
	);
	// The default `+` no longer applies once overridden.
	assert_eq!(
		directory.resolve(&parse("bob+tag@example.org")),
		Resolution::UnknownUser
	);
}

#[test]
fn catch_all_receives_unknown_local_users() {
	let directory = directory().with_catch_all([("example.org".to_string(), "bob".to_string())]);
	// Unknown user falls through to the catch-all account.
	assert_eq!(
		directory.resolve(&parse("nobody@example.org")),
		Resolution::Account("bob".to_string())
	);
	// An explicit address still wins over the catch-all.
	assert_eq!(
		directory.resolve(&parse("alice@example.org")),
		Resolution::Account("alice".to_string())
	);
	// Catch-all never makes a foreign domain local.
	assert_eq!(
		directory.resolve(&parse("nobody@elsewhere.example")),
		Resolution::NotLocal
	);
}

#[test]
fn without_catch_all_unknown_user_is_rejected() {
	assert_eq!(
		directory().resolve(&parse("nobody@example.org")),
		Resolution::UnknownUser
	);
}

#[test]
fn domain_alias_resolves_as_target_domain() {
	let directory =
		directory().with_domain_aliases([("alias.example".to_string(), "example.org".to_string())]);
	assert_eq!(
		directory.resolve(&parse("alice@alias.example")),
		Resolution::Account("alice".to_string())
	);
	// Sub-addressing still applies through the alias.
	assert_eq!(
		directory.resolve(&parse("bob+tag@ALIAS.example")),
		Resolution::Account("bob".to_string())
	);
	// The alias domain is local, so an unknown user is UnknownUser, not NotLocal.
	assert_eq!(
		directory.resolve(&parse("nobody@alias.example")),
		Resolution::UnknownUser
	);
}

#[test]
fn unaliased_foreign_domain_is_not_local() {
	assert_eq!(
		directory().resolve(&parse("alice@alias.example")),
		Resolution::NotLocal
	);
}

fn directory_with_credentials() -> Directory {
	directory().with_password_hashes([("alice".to_string(), "$argon2id$stub".to_string())])
}

#[test]
fn credentials_by_account_name() {
	let directory = directory_with_credentials();
	let (account, hash) = directory.credentials("ALICE").expect("known account");
	assert_eq!(account, "alice");
	assert_eq!(hash, "$argon2id$stub");
}

#[test]
fn credentials_by_address() {
	let directory = directory_with_credentials();
	let (account, _) = directory
		.credentials("Alice@EXAMPLE.org")
		.expect("known address");
	assert_eq!(account, "alice");
}

#[test]
fn credentials_unknown_login_is_none() {
	let directory = directory_with_credentials();
	assert!(directory.credentials("mallory").is_none());
	assert!(directory.credentials("mallory@example.org").is_none());
	assert!(directory.credentials("alice@elsewhere.example").is_none());
}

#[test]
fn authenticate_enforces_totp_second_factor() {
	let secret = b"12345678901234567890";
	let directory = Directory::new(
		["example.org".to_string()],
		[("alice@example.org".to_string(), "alice".to_string())],
	)
	.with_password_hashes([(
		"alice".to_string(),
		crate::smtp::auth::tests::hash("secret"),
	)])
	.with_totp([("alice".to_string(), crate::totp::encode_base32(secret))]);

	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	let code = crate::totp::totp(secret, now);
	// Password followed by the current 6-digit TOTP code.
	let password = format!("secret{code:06}");
	assert_eq!(
		directory.authenticate("alice", &password).as_deref(),
		Some("alice")
	);
	// A wrong code, or the bare password without a code, both fail.
	assert!(directory.authenticate("alice", "secret000000").is_none());
	assert!(directory.authenticate("alice", "secret").is_none());

	// An account without a TOTP secret authenticates with just the password.
	let plain = Directory::new(
		["example.org".to_string()],
		[("bob@example.org".to_string(), "bob".to_string())],
	)
	.with_password_hashes([("bob".to_string(), crate::smtp::auth::tests::hash("pw"))]);
	assert_eq!(plain.authenticate("bob", "pw").as_deref(), Some("bob"));
}

#[test]
fn account_without_hash_cannot_authenticate() {
	// `bob` exists in the address map but has no password hash.
	let directory = directory_with_credentials();
	assert!(directory.credentials("bob@example.org").is_none());
}

#[test]
fn list_headers_only_for_list_aliases() {
	// A plain alias is not a list.
	assert_eq!(aliased().list_headers("team@example.org"), None);
	// An alias with a list_id yields List-* headers.
	let list = directory().with_aliases([(
		"announce@example.org".to_string(),
		AliasSpec {
			members: vec!["alice@example.org".to_string()],
			senders: Vec::new(),
			hidden: true,
			list_id: Some("announce.example.org".to_string()),
		},
	)]);
	let headers = list
		.list_headers("announce@example.org")
		.expect("list headers");
	assert!(
		headers.contains("List-Id: <announce.example.org>"),
		"{headers}"
	);
	assert!(
		headers.contains("List-Post: <mailto:announce@example.org>"),
		"{headers}"
	);
	assert!(headers.contains("List-Unsubscribe:"), "{headers}");
}
