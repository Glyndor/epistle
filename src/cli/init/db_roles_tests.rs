//! The shape of the role scripts. What they do to a real cluster is
//! measured on a running stack (see docs/container.md); these pin the
//! parts that keep a failure recoverable.

use super::*;

fn session(script: &str, user: &str) -> String {
	let start = script
		.find(&format!("-U {user} <<'SQL'"))
		.unwrap_or_else(|| panic!("no session as {user}"));
	let body = &script[start..];
	body[..body.find("\nSQL\n").expect("heredoc end")].to_string()
}

#[test]
fn the_rename_and_the_takeover_are_one_transaction_of_another_superuser() {
	let work = session(HARDEN_SCRIPT, "epistle_harden");
	assert!(
		HARDEN_SCRIPT.contains("-1 -U epistle_harden"),
		"psql -1 wraps the session in one transaction"
	);
	for statement in [
		"ALTER ROLE epistle RENAME TO epistle_admin",
		"CREATE ROLE epistle LOGIN NOSUPERUSER",
		"ALTER DATABASE epistle OWNER TO epistle",
		"ALTER TABLE %s OWNER TO epistle",
		"still owned by epistle_admin",
	] {
		assert!(
			work.contains(statement),
			"{statement} must run in the transaction"
		);
	}
	assert!(
		!session(HARDEN_SCRIPT, "epistle").contains("RENAME"),
		"the session logged in as epistle cannot rename epistle"
	);
}

#[test]
fn the_temporary_superuser_is_dropped_by_the_new_admin() {
	let tail = &HARDEN_SCRIPT[HARDEN_SCRIPT.rfind("\nSQL\n").unwrap()..];
	assert!(
		tail.contains("-U epistle_admin -c 'DROP ROLE epistle_harden'"),
		"{tail}"
	);
	assert!(
		session(HARDEN_SCRIPT, "epistle").contains("DROP ROLE IF EXISTS epistle_harden"),
		"a run that stopped half way is started over"
	);
}

#[test]
fn no_password_reaches_an_argument_list() {
	for script in [INIT_SCRIPT, HARDEN_SCRIPT] {
		assert!(!script.contains("-v password="), "{script}");
		assert!(!script.contains("PASSWORD '"), "{script}");
	}
}
