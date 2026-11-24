//! What a key confined to some domains may do, and the domains hosted later.

use super::*;

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

#[test]
fn a_confined_key_cannot_make_an_alias_it_could_no_longer_reach() {
	let (_dir, config) = setup("");
	operator_made(&config, "team@example.org", &["alice@example.org"]);
	let error = refused(
		&config,
		&Change::SenderAdd {
			address: "team@example.org".into(),
			sender: "carol@example.net".into(),
		},
		&key(Some(&["example.org"])),
	);
	assert!(error.to_string().contains("sender"), "{error}");
}
