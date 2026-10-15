use super::*;

fn rule(scope: Scope, class: Option<MailClass>, mode: Mode, days: u32) -> Rule {
	Rule {
		scope,
		class,
		mode,
		days,
	}
}

fn metadata(days: u32) -> Option<Retention> {
	Some(Retention {
		mode: RetentionMode::Metadata,
		days,
	})
}

#[test]
fn without_rules_only_transactional_keeps_a_year_of_metadata() {
	let policy = Policy::default();
	assert_eq!(
		policy.retention("a", None, MailClass::Transactional),
		metadata(365)
	);
	assert_eq!(policy.retention("a", None, MailClass::Marketing), None);
	assert_eq!(policy.retention("a", None, MailClass::Personal), None);
}

#[test]
fn the_most_specific_rule_wins_per_tenant_and_account() {
	let mut policy = Policy::default();
	policy.set(rule(Scope::Server, None, Mode::Metadata, 30));
	policy.set(rule(
		Scope::Tenant("sena".into()),
		Some(MailClass::Transactional),
		Mode::Full,
		365,
	));
	policy.set(rule(Scope::Tenant("sena".into()), None, Mode::Metadata, 90));
	policy.set(rule(
		Scope::Account("notices".into()),
		Some(MailClass::Marketing),
		Mode::Off,
		0,
	));
	let full = Some(Retention {
		mode: RetentionMode::Full,
		days: 365,
	});
	assert_eq!(
		policy.retention("notices", Some("SENA"), MailClass::Transactional),
		full
	);
	assert_eq!(
		policy.retention("notices", Some("sena"), MailClass::Personal),
		metadata(90)
	);
	assert_eq!(
		policy.retention("notices", Some("sena"), MailClass::Marketing),
		None
	);
	assert_eq!(
		policy.retention("other", Some("acme"), MailClass::Transactional),
		metadata(30)
	);
	assert_eq!(
		policy.retention("other", None, MailClass::Marketing),
		metadata(30)
	);
}

#[test]
fn transactional_evidence_cannot_be_turned_off() {
	let mut policy = Policy::default();
	policy.set(rule(
		Scope::Server,
		Some(MailClass::Transactional),
		Mode::Off,
		0,
	));
	assert_eq!(
		policy.validate(),
		Err("transactional mail always keeps evidence".into())
	);
	let mut every_class = Policy::default();
	every_class.set(rule(Scope::Server, None, Mode::Off, 0));
	assert_eq!(every_class.validate(), Ok(()));
	assert_eq!(
		every_class.retention("a", None, MailClass::Transactional),
		metadata(365)
	);
}

#[test]
fn rules_are_bounded_and_names_checked() {
	let mut policy = Policy::default();
	policy.set(rule(Scope::Server, None, Mode::Metadata, MAX_DAYS + 1));
	assert!(policy.validate().is_err());
	let mut names = Policy::default();
	names.set(rule(Scope::Account("../x".into()), None, Mode::Metadata, 1));
	assert_eq!(
		names.validate(),
		Err("a tenant or account name is not valid".into())
	);
	let many = Policy {
		rules: vec![rule(Scope::Server, None, Mode::Metadata, 1); MAX_RULES + 1],
	};
	assert!(many.validate().is_err());
}

#[test]
fn set_replaces_and_the_file_round_trips() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut policy = Policy::default();
	policy.set(rule(Scope::Tenant("sena".into()), None, Mode::Metadata, 90));
	policy.set(rule(Scope::Tenant("sena".into()), None, Mode::Full, 365));
	assert_eq!(policy.rules.len(), 1);
	save(dir.path(), &policy).expect("save");
	assert_eq!(load(dir.path()).expect("load"), policy);
	let text = std::fs::read_to_string(dir.path().join("policy.json")).expect("read");
	assert!(text.contains("\"scope\": \"tenant\""), "{text}");
}
