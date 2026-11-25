//! Role addresses and sub-address tags, which a key may not use.

use super::*;

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
fn a_key_cannot_remove_or_edit_the_alias_of_a_role_address() {
	let (_dir, config) = setup("");
	operator_made(
		&config,
		"postmaster@example.org",
		&["alice@example.org", "bob@example.org"],
	);
	let before = std::fs::read_to_string(crate::aliases::path(&config.data_dir)).unwrap();
	let changes = [
		Change::Remove {
			address: "postmaster@example.org".into(),
		},
		Change::MemberAdd {
			address: "postmaster@example.org".into(),
			member: "bob@example.org".into(),
		},
		Change::MemberRemove {
			address: "postmaster@example.org".into(),
			member: "bob@example.org".into(),
		},
		Change::SenderAdd {
			address: "postmaster@example.org".into(),
			sender: "alice@example.org".into(),
		},
		Change::SenderRemove {
			address: "postmaster@example.org".into(),
			sender: "alice@example.org".into(),
		},
	];
	for change in changes {
		for origin in [key(None), key(Some(&["example.org"]))] {
			let error = refused(&config, &change, &origin);
			assert!(
				error.to_string().contains("role address"),
				"{change:?}: {error}"
			);
			assert!(
				matches!(
					edit::commit(&config, &change, &origin),
					Err(AliasError::Invalid(_))
				),
				"{change:?}"
			);
		}
	}
	assert_eq!(
		std::fs::read_to_string(crate::aliases::path(&config.data_dir)).unwrap(),
		before,
		"nothing was written"
	);
	edit::commit(
		&config,
		&Change::MemberRemove {
			address: "postmaster@example.org".into(),
			member: "bob@example.org".into(),
		},
		&Origin::Operator,
	)
	.expect("the operator may edit it");
}

#[test]
fn the_names_a_certificate_authority_mails_are_role_addresses_with_or_without_a_tag() {
	let (_dir, config) = setup("");
	for local in [
		"admin",
		"Administrator",
		"root",
		"ssladmin",
		"tlsrpt",
		"mailer-daemon",
		"postmaster+x",
		"admin+anything",
		"HOSTMASTER+a+b",
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
		.expect("the operator may");
	}
	edit::preview(
		&config,
		&new("administration@example.org", &["alice@example.org"]),
		&key(None),
	)
	.expect("a name that only starts like a role is an ordinary one");
}

#[test]
fn an_alias_address_with_a_tag_is_not_for_a_key_whether_or_not_the_account_exists() {
	let (_dir, config) = setup("");
	for address in [
		"alice+shop@example.org",
		"ALICE+x+y@example.org",
		"zed+shop@example.org",
		"+lead@example.org",
		"a+@example.org",
	] {
		let error = refused(&config, &new(address, &["bob@example.org"]), &key(None));
		assert!(
			error.to_string().contains("tagged form"),
			"{address}: {error}"
		);
		assert_eq!(
			refused(
				&config,
				&new(address, &["bob@example.org"]),
				&key(Some(&["example.org"]))
			),
			error
		);
		edit::preview(
			&config,
			&new(address, &["bob@example.org"]),
			&Origin::Operator,
		)
		.expect("the operator may");
	}
}
