//! The rules for the operator and for a key of the API, and the attacks a key
//! can try: another tenant's domain, a member that is not local or not in the
//! key's domains, an address that collides, a role address, odd spellings and
//! the sizes.

use crate::aliases::edit::{self, NewAlias, rules::MAX_MEMBERS};
use crate::aliases::{AliasError, Change, Origin};
use crate::config::Config;

/// Two domains, two accounts in the first and one in the second.
fn setup(extra: &str) -> (tempfile::TempDir, Config) {
	let dir = tempfile::tempdir().expect("dir");
	let data = dir.path().join("data");
	std::fs::create_dir(&data).expect("data dir");
	let data = data.canonicalize().expect("canonical");
	std::fs::write(
		data.join("accounts.toml"),
		"[[accounts]]\nname = \"alice\"\naddresses = [\"alice@example.org\"]\npassword_hash = \"stub\"\n\n\
		 [[accounts]]\nname = \"bob\"\naddresses = [\"bob@example.org\"]\npassword_hash = \"stub\"\n\n\
		 [[accounts]]\nname = \"carol\"\naddresses = [\"carol@example.net\"]\npassword_hash = \"stub\"\n",
	)
	.expect("accounts");
	let file = dir.path().join("mail.toml");
	std::fs::write(
		&file,
		format!(
			"hostname = \"mail.example.org\"\ndata_dir = {data:?}\n\
			 domains = [\"example.org\", \"example.net\"]\n\
			 [domain_aliases]\n\"alias.example.org\" = \"example.org\"\n{extra}\n"
		),
	)
	.expect("config");
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).expect("chmod");
	}
	let config = Config::load(&file).expect("loads");
	(dir, config)
}

fn new(address: &str, members: &[&str]) -> Change {
	Change::Add(NewAlias {
		address: address.into(),
		members: members.iter().map(|member| member.to_string()).collect(),
		senders: Vec::new(),
		list_id: None,
		hidden: true,
	})
}

fn key(domains: Option<&[&str]>) -> Origin {
	Origin::Api {
		confined_to: domains.map(|list| list.iter().map(|d| d.to_string()).collect()),
	}
}

fn refused(config: &Config, change: &Change, origin: &Origin) -> AliasError {
	edit::preview(config, change, origin).expect_err("refused")
}

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
fn a_confined_key_gets_one_answer_for_a_member_that_is_missing_and_one_that_is_not_its_own() {
	let (_dir, config) = setup("");
	let origin = key(Some(&["example.org"]));
	// carol exists, in a domain the key may not use; ghost does not exist.
	let other = refused(
		&config,
		&new("team@example.org", &["carol@example.net"]),
		&origin,
	);
	let missing = refused(
		&config,
		&new("team@example.org", &["carol2@example.net"]),
		&origin,
	);
	let (AliasError::Invalid(other), AliasError::Invalid(missing)) = (&other, &missing) else {
		panic!("{other:?} {missing:?}");
	};
	assert_eq!(
		other.replace("carol@", "x@"),
		missing.replace("carol2@", "x@"),
		"the two refusals differ"
	);
}

#[test]
fn a_confined_key_cannot_add_an_alias_in_a_domain_it_may_not_use() {
	let (_dir, config) = setup("");
	let origin = key(Some(&["example.org"]));
	let outside = refused(
		&config,
		&new("team@example.net", &["alice@example.org"]),
		&origin,
	);
	let unhosted = refused(
		&config,
		&new("team@nowhere.example", &["alice@example.org"]),
		&origin,
	);
	assert_eq!(
		outside, unhosted,
		"a hosted domain of another tenant looks like one that is not hosted"
	);
	let alias_domain = refused(
		&config,
		&new("team@alias.example.org", &["alice@example.org"]),
		&origin,
	);
	assert_eq!(alias_domain, unhosted, "so does a domain alias");
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
fn role_addresses_are_the_operators_and_not_a_key_s() {
	let (_dir, config) = setup("");
	for local in [
		"postmaster",
		"ABUSE",
		"hostmaster",
		"webmaster",
		"security",
		"noc",
	] {
		let address = format!("{local}@example.org");
		let error = refused(&config, &new(&address, &["alice@example.org"]), &key(None));
		assert!(
			error.to_string().contains("role address"),
			"{address}: {error}"
		);
		edit::preview(
			&config,
			&new(&address, &["alice@example.org"]),
			&Origin::Operator,
		)
		.expect("the operator may point a role address at an alias");
	}
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
fn a_removal_outside_the_key_s_domains_is_as_absent_as_one_that_does_not_exist() {
	let (_dir, config) = setup("");
	edit::commit(
		&config,
		&new("team@example.net", &["carol@example.net"]),
		&key(None),
	)
	.expect("add");
	let config =
		Config::load(&config.data_dir.parent().unwrap().join("mail.toml")).expect("reload");
	let confined = key(Some(&["example.org"]));
	let remove = |address: &str| Change::Remove {
		address: address.into(),
	};
	let outside = refused(&config, &remove("team@example.net"), &confined);
	let missing = refused(&config, &remove("ghost@example.org"), &confined);
	assert_eq!(
		outside.to_string().replace("team@example.net", "x"),
		missing.to_string().replace("ghost@example.org", "x")
	);
	assert!(matches!(outside, AliasError::NotFound(_)));
	edit::preview(
		&config,
		&remove("team@example.net"),
		&key(Some(&["example.net"])),
	)
	.expect("its own");
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

#[test]
fn a_domain_with_an_alias_in_the_state_file_cannot_be_removed_even_from_an_older_snapshot() {
	let (_dir, config) = setup("");
	edit::commit(
		&config,
		&new("team@example.net", &["carol@example.net"]),
		&key(None),
	)
	.expect("add");
	// `config` is the snapshot from before the write.
	assert!(config.alias.is_empty());
	let error = crate::domain::state::edit::commit(
		&config,
		&crate::domain::state::Change::Remove {
			name: "example.net".into(),
		},
	)
	.expect_err("in use");
	assert!(
		error.to_string().contains("alias team@example.net"),
		"{error}"
	);
}

#[test]
fn a_domain_hosted_after_the_configuration_was_loaded_takes_aliases() {
	let (_dir, config) = setup("");
	crate::domain::state::edit::commit(
		&config,
		&crate::domain::state::Change::Add {
			name: "example.com".into(),
			role: crate::domain::state::StoredRole::Full,
			dkim: None,
			srs_secret: None,
		},
	)
	.expect("host the domain");
	// `config` is the snapshot from before the domain was hosted.
	assert!(!config.domains.iter().any(|domain| domain == "example.com"));
	edit::commit(
		&config,
		&new("team@example.com", &["alice@example.org"]),
		&Origin::Operator,
	)
	.expect("the alias goes to the domain as it is now");
}
