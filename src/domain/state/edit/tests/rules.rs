//! What each change accepts and refuses, with the reason it gives.

use super::super::super::file::StoredRole;
use super::super::super::tests::Fixture;
use super::*;

const LISTENER: &str = "[[listeners]]\nkind = \"smtp\"\nport = 2525\n";

fn add(name: &str) -> Change {
	Change::Add {
		name: name.into(),
		role: StoredRole::Full,
		dkim: None,
		srs_secret: None,
	}
}

fn refused(fixture: &Fixture, change: Change) -> EditError {
	commit(&fixture.load(), &change).expect_err("refused")
}

#[test]
fn a_new_domain_is_stored_lowercase_and_trimmed() {
	let fixture = Fixture::new("");
	let done = commit(&fixture.load(), &add("  NEW.Example.ORG ")).unwrap();
	assert!(done.changed);
	assert!(done.after.domain("new.example.org").is_some());
	assert_eq!(done.after.names().last().unwrap(), "new.example.org");
}

#[test]
fn hostile_names_are_refused_with_the_reason() {
	let fixture = Fixture::new("");
	let cases = [
		("example.org.", "domain"),
		("bücher.example", "xn--bcher-kva.example"),
		("раураl.com", "domain"),
		("exa mple.org", "domain"),
		("", "must not be empty"),
		("a..example", "domain"),
		(&"a".repeat(260), "domain"),
	];
	for (name, reason) in cases {
		match refused(&fixture, add(name)) {
			EditError::Invalid(message) => assert!(message.contains(reason), "{name:?}: {message}"),
			other => panic!("{name:?}: {other:?}"),
		}
	}
	assert!(fixture.state().is_none(), "a refusal writes nothing");
}

#[test]
fn a_hosted_name_an_alias_or_an_alias_target_cannot_be_added() {
	let fixture = Fixture::new("[domain_aliases]\n\"alias.example.net\" = \"example.org\"\n");
	for name in ["EXAMPLE.org", "alias.example.net"] {
		assert!(
			matches!(refused(&fixture, add(name)), EditError::Exists(_)),
			"{name}"
		);
	}
	let refusal = refused(&fixture, add("Example.org")).to_string();
	assert_eq!(refusal, "domain Example.org is already configured");
}

#[test]
fn an_unknown_domain_is_not_found_for_every_change() {
	let fixture = Fixture::new("");
	let name = || "ghost.example.org".to_string();
	for change in [
		Change::Remove { name: name() },
		Change::SetRole {
			name: name(),
			role: StoredRole::SendOnly,
		},
		Change::SetEnabled {
			name: name(),
			enabled: false,
		},
		Change::AliasRemove { alias: name() },
		Change::AliasAdd {
			alias: "alias.example.net".into(),
			target: name(),
		},
	] {
		assert!(
			matches!(refused(&fixture, change.clone()), EditError::NotFound(_)),
			"{change:?}"
		);
	}
}

#[test]
fn removal_is_refused_while_something_uses_the_domain() {
	let fixture = Fixture::new(
		"[[accounts]]\nname = \"alice\"\naddresses = [\"alice@other.example.org\"]\n\
		 password_hash = \"$argon2id$v=19$m=65536,t=2,p=1$YWFhYWFhYWFhYWFhYWFhYQ$0000000000000000000000000000000000000000000\"\n",
	);
	match refused(
		&fixture,
		Change::Remove {
			name: "other.example.org".into(),
		},
	) {
		EditError::InUse(message) => assert!(message.contains("alice"), "{message}"),
		other => panic!("{other:?}"),
	}
	let done = commit(
		&fixture.load(),
		&Change::Remove {
			name: "EXAMPLE.org".into(),
		},
	)
	.unwrap();
	assert_eq!(done.after.names(), ["other.example.org"]);
}

#[test]
fn removal_is_refused_while_the_configuration_file_names_the_domain() {
	let fixture = Fixture::new("[[tenant]]\nname = \"acme\"\ndomains = [\"other.example.org\"]\n");
	let message = refused(
		&fixture,
		Change::Remove {
			name: "other.example.org".into(),
		},
	)
	.to_string();
	assert!(message.contains("tenant acme"), "{message}");
}

#[test]
fn the_last_enabled_domain_of_a_server_with_listeners_stays_on() {
	let fixture = Fixture::new(LISTENER);
	let off = |name: &str| Change::SetEnabled {
		name: name.into(),
		enabled: false,
	};
	commit(&fixture.load(), &off("other.example.org")).unwrap();
	assert!(matches!(
		refused(&fixture, off("example.org")),
		EditError::Policy(_)
	));
	let without = Fixture::new("");
	commit(&without.load(), &off("other.example.org")).unwrap();
	commit(&without.load(), &off("example.org")).expect("no listeners, no rule");
}

#[test]
fn a_switched_off_domain_keeps_its_role_and_gets_it_back() {
	let fixture = Fixture::new("");
	let config = fixture.load();
	commit(
		&config,
		&Change::SetRole {
			name: "example.org".into(),
			role: StoredRole::ReceiveOnly,
		},
	)
	.unwrap();
	let off = commit(
		&fixture.load(),
		&Change::SetEnabled {
			name: "example.org".into(),
			enabled: false,
		},
	)
	.unwrap();
	assert_eq!(off.config.disabled_domains, ["example.org"]);
	let on = commit(
		&fixture.load(),
		&Change::SetEnabled {
			name: "example.org".into(),
			enabled: true,
		},
	)
	.unwrap();
	assert!(on.config.disabled_domains.is_empty());
	assert_eq!(on.config.receive_only_domains, ["example.org"]);
}

#[test]
fn an_alias_targets_a_hosted_domain_once_and_never_names_one() {
	let fixture = Fixture::new("");
	let alias = |alias: &str, target: &str| Change::AliasAdd {
		alias: alias.into(),
		target: target.into(),
	};
	let done = commit(&fixture.load(), &alias("Alias.Example.NET", "EXAMPLE.org")).unwrap();
	assert_eq!(done.after.aliases["alias.example.net"], "example.org");
	assert!(matches!(
		refused(&fixture, alias("alias.example.net", "other.example.org")),
		EditError::Exists(_)
	));
	assert!(matches!(
		refused(&fixture, alias("other.example.org", "example.org")),
		EditError::Exists(_)
	));
	assert!(matches!(
		refused(&fixture, alias("bücher.example", "example.org")),
		EditError::Invalid(_)
	));
	let removed = commit(
		&fixture.load(),
		&Change::AliasRemove {
			alias: "ALIAS.example.net".into(),
		},
	)
	.unwrap();
	assert!(removed.after.aliases.is_empty());
}

#[test]
fn import_puts_the_configuration_file_lists_back_and_keeps_what_was_made() {
	let fixture = Fixture::new("");
	let config = fixture.load();
	commit(&config, &add("new.example")).unwrap();
	let mut keep = fixture.state().unwrap();
	keep.domain_mut("example.org").unwrap().srs_secret = Some("k".repeat(40));
	std::fs::write(fixture.state_path(), keep.render().unwrap()).unwrap();
	let done = commit(&fixture.load(), &Change::Import).unwrap();
	assert_eq!(done.after.names(), ["example.org", "other.example.org"]);
	assert_eq!(
		done.after.domain("example.org").unwrap().srs_secret,
		Some("k".repeat(40)),
		"a domain that stays keeps its secret"
	);
	assert_eq!(done.after.seed_digest, config.domain_seed.digest());
}
