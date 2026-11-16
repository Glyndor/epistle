use super::*;
use crate::imap::special_use::Roles;

const RULES: &str = "[storage.cleanup]\n\
[[storage.cleanup.rule]]\nscope = 'server'\nfolder = 'trash'\ndays = 30\n\
[[storage.cleanup.rule]]\nscope = 'server'\nfolder = 'junk'\ndays = 60\n\
[[storage.cleanup.rule]]\nscope = 'tenant'\nname = 'acme'\nfolder = 'trash'\ndays = 21\n\
[[storage.cleanup.rule]]\nscope = 'domain'\nname = 'example.org'\nfolder = 'trash'\ndays = 14\n\
[[storage.cleanup.rule]]\nscope = 'domain'\nname = 'example.org'\nfolder = 'rejects'\ndays = 3\n\
[[storage.cleanup.rule]]\nscope = 'account'\nname = 'keeper@example.org'\nfolder = 'trash'\ndays = 0\n\
[[storage.cleanup.rule]]\nscope = 'account'\nname = 'short@example.org'\nfolder = 'Old mail'\ndays = 2\n";

fn days(policy: &Policy, account: &str, folder: &str) -> Option<u64> {
	let keys = folder_keys(folder, &Roles::default());
	policy.operator_days(&policy.subject(account), &keys)
}

#[test]
fn the_narrower_scope_wins_and_a_zero_keeps_for_ever() {
	let policy = policy(RULES);
	// domain beats server, tenant beats server, account beats domain
	assert_eq!(days(&policy, "a@example.org", "Trash"), Some(14));
	assert_eq!(days(&policy, "a@other.example", "Trash"), Some(21));
	assert_eq!(days(&policy, "a@third.example", "Trash"), Some(30));
	assert_eq!(days(&policy, "keeper@example.org", "Trash"), Some(0));
	assert_eq!(days(&policy, "KEEPER@EXAMPLE.ORG", "Trash"), Some(0));
}

#[test]
fn a_folder_name_beats_the_role_in_the_same_scope_and_a_rule_for_nothing_says_nothing() {
	let policy = policy(RULES);
	// `rejects` names the folder; `junk` is the role it has. Both exist in the
	// server scope, and the domain's `rejects` is narrower still.
	assert_eq!(days(&policy, "a@example.org", "Rejects"), Some(3));
	assert_eq!(days(&policy, "a@other.example", "Rejects"), Some(60));
	assert_eq!(days(&policy, "a@example.org", "Junk"), Some(60));
	assert_eq!(days(&policy, "short@example.org", "Old mail"), Some(2));
	assert_eq!(days(&policy, "a@example.org", "Old mail"), None);
	assert_eq!(days(&policy, "a@example.org", "Drafts"), None);
}

#[test]
fn a_folder_with_a_recorded_role_is_found_by_the_role() {
	let policy = policy(RULES);
	let dir = tempfile::tempdir().expect("tempdir");
	crate::imap::mailbox::ensure_defaults(dir.path(), "a@example.org").expect("defaults");
	crate::imap::mailbox::create(dir.path(), "a@example.org", "Papelera").expect("create");
	crate::imap::special_use::roles::set(
		dir.path(),
		"a@example.org",
		crate::imap::special_use::Role::Trash,
		"Papelera",
	)
	.expect("role");
	let roles = Roles::load(dir.path(), "a@example.org");
	let subject = policy.subject("a@example.org");
	assert_eq!(
		policy.operator_days(&subject, &folder_keys("Papelera", &roles)),
		Some(14)
	);
	// The English name lost the role with it.
	assert_eq!(
		policy.operator_days(&subject, &folder_keys("Trash", &roles)),
		None
	);
}

#[test]
fn the_account_may_shorten_the_operators_retention_and_never_lengthen_it() {
	for (operator, account, expected) in [
		(None, None, None),
		(Some(30), None, Some(30)),
		(Some(30), Some(7), Some(7)),
		(Some(30), Some(90), Some(30)),
		(Some(30), Some(0), Some(30)),
		(Some(0), Some(90), Some(90)),
		(Some(0), None, Some(0)),
		(None, Some(90), Some(90)),
	] {
		assert_eq!(
			combine(operator, account),
			expected,
			"{operator:?} {account:?}"
		);
	}
}
