use super::*;

#[test]
fn an_account_preference_round_trips_and_clears() {
	let dir = tempfile::tempdir().expect("tempdir");
	crate::imap::mailbox::ensure_defaults(dir.path(), "a@example.org").expect("defaults");
	assert_eq!(Prefs::load(dir.path(), "a@example.org"), Prefs::default());
	Prefs::set(dir.path(), "a@example.org", "Trash", 7).expect("set");
	Prefs::set(dir.path(), "a@example.org", "Old mail", 0).expect("set");
	let prefs = Prefs::load(dir.path(), "a@example.org");
	assert_eq!(
		prefs.days_for(&["name:trash".to_string(), "word:trash".to_string()]),
		Some(7)
	);
	assert_eq!(prefs.days_for(&[rule_key("Old mail")]), Some(0));
	assert_eq!(prefs.days_for(&[rule_key("Drafts")]), None);
	Prefs::clear(dir.path(), "a@example.org", "trash").expect("clear");
	Prefs::clear(dir.path(), "a@example.org", "old mail").expect("clear");
	assert!(!dir.path().join("accounts/a@example.org/.cleanup").exists());
}

#[test]
fn a_hostile_account_name_has_no_preferences_and_cannot_be_written() {
	let dir = tempfile::tempdir().expect("tempdir");
	assert_eq!(Prefs::load(dir.path(), "../x"), Prefs::default());
	assert!(Prefs::set(dir.path(), "../x", "trash", 1).is_err());
}
