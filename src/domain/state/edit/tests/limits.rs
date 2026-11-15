//! Limits survive round trips and all changes validate as one transaction.

use super::super::super::tests::Fixture;
use super::*;

fn set(quota: Option<Option<u64>>, rate: Option<Option<u32>>) -> Change {
	Change::Set {
		name: "example.org".into(),
		role: None,
		quota,
		submission_rate: rate,
	}
}

#[test]
fn clearing_a_seed_limit_survives_restart_and_an_empty_limits_table() {
	let fixture = Fixture::new(
		"[domain_quotas]\n'example.org' = 100\n[domain_submission_limits]\n'example.org' = 7\n",
	);
	let config = fixture.load();
	let done = commit(&config, &set(Some(None), None)).unwrap();
	assert!(!done.config.domain_quotas.contains_key("example.org"));
	assert_eq!(done.config.domain_submission_limits["example.org"], 7);
	assert_eq!(fixture.load().domain_submission_limits["example.org"], 7);
	// Keep using the old config: a queued writer must preserve the disk change.
	commit(&config, &set(None, Some(None))).unwrap();
	let loaded = fixture.load();
	assert!(!loaded.domain_quotas.contains_key("example.org"));
	assert!(!loaded.domain_submission_limits.contains_key("example.org"));
	let file = fixture.state().unwrap();
	assert_eq!(DomainsFile::parse(&file.render().unwrap()).unwrap(), file);
	assert!(
		!commit(&config, &set(Some(None), Some(None)))
			.unwrap()
			.changed
	);
}

#[test]
fn invalid_limits_do_not_leave_a_new_role_or_a_partial_limit() {
	let fixture = Fixture::new("");
	let config = fixture.load();
	for (quota, submission_rate) in [
		(Some(Some(u64::MAX)), None),
		(Some(Some(42)), Some(Some(0))),
	] {
		let change = Change::Set {
			name: "example.org".into(),
			role: Some(super::super::super::file::StoredRole::SendOnly),
			quota,
			submission_rate,
		};
		assert!(matches!(
			commit(&config, &change),
			Err(EditError::Invalid(_))
		));
		assert!(fixture.state().is_none());
	}
}

#[test]
fn quotas_are_validated_against_tenant_caps_with_the_new_role() {
	let fixture =
		Fixture::new("[[tenant]]\nname = 'one'\ndomains = ['example.org']\nquota_bytes = 100\n");
	let change = Change::Set {
		name: "example.org".into(),
		role: Some(super::super::super::file::StoredRole::SendOnly),
		quota: Some(Some(101)),
		submission_rate: Some(Some(7)),
	};
	assert!(matches!(
		commit(&fixture.load(), &change),
		Err(EditError::Invalid(_))
	));
	assert!(
		fixture.state().is_none(),
		"validate the combined result before writing"
	);
}

#[test]
fn a_set_that_names_nothing_is_refused_like_the_command_does() {
	let fixture = Fixture::new("");
	let config = fixture.load();
	let change = Change::Set {
		name: "example.org".into(),
		role: None,
		quota: None,
		submission_rate: None,
	};
	assert!(matches!(
		commit(&config, &change),
		Err(EditError::Invalid(message)) if message == "domain set: nothing to change"
	));
	assert!(fixture.state().is_none());
}
