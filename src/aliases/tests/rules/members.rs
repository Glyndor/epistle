//! Who a member may be, what collides, the spellings and the sizes.

use super::*;

#[test]
fn the_operator_may_name_a_member_the_directory_cannot_route_to() {
	let (_dir, config) = setup("");
	let change = new("team@example.org", &["someone@elsewhere.example"]);
	edit::preview(&config, &change, &Origin::Operator).expect("the command always could");
}

#[test]
fn a_key_names_only_addresses_of_accounts_that_exist() {
	let (_dir, config) = setup("");
	let origin = key(None);
	edit::preview(
		&config,
		&new(
			"team@example.org",
			&["alice@example.org", "carol@example.net"],
		),
		&origin,
	)
	.expect("two accounts, in two domains the key may use");
	for member in [
		"someone@elsewhere.example",
		"ghost@example.org",
		"ALICE@example.org.evil.test",
	] {
		let error = refused(&config, &new("team@example.org", &[member]), &origin);
		assert!(
			matches!(&error, AliasError::Invalid(message) if message.ends_with("is not an address of a local account")),
			"{member}: {error}"
		);
	}
}

#[test]
fn an_unconfined_key_gets_the_messages_of_the_command() {
	let (_dir, config) = setup("");
	let operator = refused(
		&config,
		&new("team@nowhere.example", &["alice@example.org"]),
		&Origin::Operator,
	);
	let api = refused(
		&config,
		&new("team@nowhere.example", &["alice@example.org"]),
		&key(None),
	);
	assert_eq!(operator, api);
	assert_eq!(
		api.to_string(),
		"alias address: nowhere.example is not a domain this server handles"
	);
}

#[test]
fn an_address_an_account_holds_cannot_be_an_alias() {
	let (_dir, config) = setup("");
	for origin in [Origin::Operator, key(None), key(Some(&["example.org"]))] {
		let error = refused(
			&config,
			&new("alice@example.org", &["bob@example.org"]),
			&origin,
		);
		assert!(
			error.to_string().contains("already used by an account"),
			"{error}"
		);
	}
}

#[test]
fn an_address_a_masked_address_holds_cannot_be_an_alias() {
	let (_dir, config) = setup("");
	let store = crate::directory_store::AccountStore::open(
		&config.data_dir,
		config.domains.clone(),
		config.domain_aliases.clone(),
		config.accounts.clone(),
	)
	.expect("store");
	let masked = store
		.add_masked("alice", "shop", "example.org", 0)
		.expect("a masked address")
		.address;
	let error = refused(&config, &new(&masked, &["alice@example.org"]), &key(None));
	assert!(
		error
			.to_string()
			.contains("already used by a masked address"),
		"{error}"
	);
}

#[test]
fn an_alias_that_exists_is_a_conflict_with_the_text_of_the_command() {
	let (_dir, config) = setup("");
	edit::commit(
		&config,
		&new("team@example.org", &["alice@example.org"]),
		&key(None),
	)
	.expect("first");
	let again = refused(
		&config,
		&new("TEAM@example.org", &["bob@example.org"]),
		&key(None),
	);
	assert_eq!(
		again,
		AliasError::Exists("alias TEAM@example.org already exists".into())
	);
	let operator = refused(
		&config,
		&new("TEAM@example.org", &["bob@example.org"]),
		&Origin::Operator,
	);
	assert_eq!(operator, again);
}

#[test]
fn odd_spellings_are_stored_in_one_form_and_control_characters_are_refused() {
	let (_dir, config) = setup("");
	let origin = key(None);
	let done = edit::preview(
		&config,
		&new(
			"Team.One@EXAMPLE.org",
			&["ALICE@Example.Org", "alice@example.org"],
		),
		&origin,
	)
	.expect("case does not matter");
	assert_eq!(done.after.aliases[0].address, "team.one@example.org");
	assert_eq!(
		done.after.aliases[0].members,
		["alice@example.org"],
		"a member listed twice is kept once"
	);
	for address in [
		"te\u{0}am@example.org",
		"team\n@example.org",
		"te am@example.org",
		"team@example.org\r\nBcc: x@y.test",
		"team\u{2028}@example.org",
		"",
	] {
		assert!(
			matches!(
				refused(&config, &new(address, &["alice@example.org"]), &origin),
				AliasError::Invalid(_)
			),
			"{address:?}"
		);
	}
	// A punycode label is a domain that is not hosted; the U-label spelling of
	// a hosted domain does not slip in as another name.
	assert!(matches!(
		refused(
			&config,
			&new("team@xn--exmple-cua.org", &["alice@example.org"]),
			&origin
		),
		AliasError::Invalid(_)
	));
}

#[test]
fn the_number_of_members_is_bounded_and_an_alias_needs_one() {
	let (_dir, config) = setup("");
	let many: Vec<String> = (0..=MAX_MEMBERS)
		.map(|n| format!("m{n}@example.org"))
		.collect();
	let many: Vec<&str> = many.iter().map(String::as_str).collect();
	let error = refused(&config, &new("team@example.org", &many), &Origin::Operator);
	assert!(error.to_string().contains("more than"), "{error}");
	let error = refused(&config, &new("team@example.org", &[]), &key(None));
	assert_eq!(
		error,
		AliasError::Invalid("alias team@example.org has no members".into())
	);
}

#[test]
fn members_come_and_go_by_the_same_rules() {
	let (_dir, config) = setup("");
	edit::commit(
		&config,
		&new("team@example.org", &["alice@example.org"]),
		&key(None),
	)
	.expect("add");
	let config =
		Config::load(&config.data_dir.parent().unwrap().join("mail.toml")).expect("reload");
	let add = |member: &str| Change::MemberAdd {
		address: "team@example.org".into(),
		member: member.into(),
	};
	edit::preview(&config, &add("bob@example.org"), &key(None)).expect("a local account");
	assert!(matches!(
		refused(&config, &add("someone@elsewhere.example"), &key(None)),
		AliasError::Invalid(_)
	));
	assert!(matches!(
		refused(&config, &add("alice@example.org"), &key(None)),
		AliasError::Exists(_)
	));
	assert!(matches!(
		refused(
			&config,
			&add("bob@example.org"),
			&key(Some(&["example.net"]))
		),
		AliasError::NotFound(_)
	));
}
