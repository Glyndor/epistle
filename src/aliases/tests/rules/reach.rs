//! An alias, a member or a sender whose account reaches outside the key's domains.

use super::*;

/// An account with an address inside and one outside a key's domains.
pub(super) fn with_split_account(config: &Config) {
	let path = config.data_dir.join("accounts.toml");
	let mut text = std::fs::read_to_string(&path).unwrap();
	text.push_str(
		"\n[[accounts]]\nname = \"dave\"\naddresses = [\"dave@example.org\", \"dave@example.net\"]\npassword_hash = \"stub\"\n",
	);
	std::fs::write(path, text).unwrap();
}

#[test]
fn a_member_whose_account_reaches_outside_the_key_s_domains_is_not_a_local_account() {
	let (_dir, config) = setup("");
	with_split_account(&config);
	let confined = key(Some(&["example.org"]));
	let split = refused(
		&config,
		&new("team@example.org", &["dave@example.org"]),
		&confined,
	);
	let absent = refused(
		&config,
		&new("team@example.org", &["nobody@example.org"]),
		&confined,
	);
	assert_eq!(
		split.to_string().replace("dave", "x"),
		absent.to_string().replace("nobody", "x")
	);
	assert!(matches!(split, AliasError::Invalid(_)));
	assert!(matches!(
		refused(
			&config,
			&Change::MemberAdd {
				address: "team@example.org".into(),
				member: "dave@example.org".into(),
			},
			&confined,
		),
		AliasError::Invalid(_) | AliasError::NotFound(_)
	));
	edit::preview(
		&config,
		&new("team@example.org", &["dave@example.org"]),
		&key(None),
	)
	.expect("an unconfined key may name the account");
	edit::preview(
		&config,
		&new("team@example.org", &["dave@example.org"]),
		&Origin::Api {
			confined_to: Some(vec!["example.org".into(), "example.net".into()]),
		},
	)
	.expect("a key that reaches the whole account may");
}

#[test]
fn an_alias_with_a_member_or_a_sender_outside_the_key_s_domains_is_as_absent_as_a_missing_one() {
	let (_dir, config) = setup("");
	operator_made(
		&config,
		"mixed@example.org",
		&["alice@example.org", "carol@example.net"],
	);
	operator_made(&config, "sent@example.org", &["alice@example.org"]);
	edit::commit(
		&config,
		&Change::SenderAdd {
			address: "sent@example.org".into(),
			sender: "carol@example.net".into(),
		},
		&Origin::Operator,
	)
	.unwrap();
	let confined = key(Some(&["example.org"]));
	let missing = Change::Remove {
		address: "ghost@example.org".into(),
	};
	let expected = refused(&config, &missing, &confined)
		.to_string()
		.replace("ghost@example.org", "ADDRESS");
	assert_eq!(expected, "alias ADDRESS not found");
	for address in ["mixed@example.org", "sent@example.org"] {
		let changes = [
			Change::Remove {
				address: address.into(),
			},
			Change::MemberAdd {
				address: address.into(),
				member: "bob@example.org".into(),
			},
			Change::MemberRemove {
				address: address.into(),
				member: "alice@example.org".into(),
			},
			Change::SenderAdd {
				address: address.into(),
				sender: "bob@example.org".into(),
			},
			Change::SenderRemove {
				address: address.into(),
				sender: "carol@example.net".into(),
			},
		];
		for change in changes {
			let error = refused(&config, &change, &confined);
			assert!(
				matches!(error, AliasError::NotFound(_)),
				"{change:?}: {error}"
			);
			assert_eq!(error.to_string().replace(address, "ADDRESS"), expected);
		}
	}
	edit::commit(
		&config,
		&Change::Remove {
			address: "mixed@example.org".into(),
		},
		&key(None),
	)
	.expect("an unconfined key reaches it");
}

#[test]
fn an_alias_whose_member_account_reaches_outside_the_key_s_domains_is_as_absent_as_a_missing_one() {
	let (_dir, config) = setup("");
	with_split_account(&config);
	operator_made(&config, "team@example.org", &["dave@example.org"]);
	operator_made(&config, "sent@example.org", &["alice@example.org"]);
	edit::commit(
		&config,
		&Change::SenderAdd {
			address: "sent@example.org".into(),
			sender: "dave@example.org".into(),
		},
		&Origin::Operator,
	)
	.unwrap();
	let confined = key(Some(&["example.org"]));
	let expected = refused(
		&config,
		&Change::Remove {
			address: "ghost@example.org".into(),
		},
		&confined,
	)
	.to_string()
	.replace("ghost@example.org", "ADDRESS");
	for address in ["team@example.org", "sent@example.org"] {
		let changes = [
			Change::Remove {
				address: address.into(),
			},
			Change::MemberAdd {
				address: address.into(),
				member: "bob@example.org".into(),
			},
			Change::MemberRemove {
				address: address.into(),
				member: "alice@example.org".into(),
			},
			Change::SenderAdd {
				address: address.into(),
				sender: "bob@example.org".into(),
			},
			Change::SenderRemove {
				address: address.into(),
				sender: "dave@example.org".into(),
			},
		];
		for change in changes {
			let error = refused(&config, &change, &confined);
			assert!(
				matches!(error, AliasError::NotFound(_)),
				"{change:?}: {error}"
			);
			assert_eq!(error.to_string().replace(address, "ADDRESS"), expected);
		}
	}
	edit::commit(
		&config,
		&Change::Remove {
			address: "team@example.org".into(),
		},
		&Origin::Api {
			confined_to: Some(vec!["example.org".into(), "example.net".into()]),
		},
	)
	.expect("a key that reaches the whole account may");
}
