//! A quota of 0 means no limit, as on every other delivery path.

use super::*;
use crate::test_fixtures as fixtures;

#[test]
fn a_zero_quota_is_unlimited() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session =
		Session::new("mail.example.org", dir.path().to_path_buf(), directory()).with_quota_limit(0);
	session.command_line(&format!("a1 LOGIN alice {}", fixtures::password()));

	let append = text(&session.command_line("a2 APPEND INBOX {200}"));
	assert!(!append.contains("OVERQUOTA"), "{append}");
	assert!(append.starts_with("+ "), "{append}");

	let mut session =
		Session::new("mail.example.org", dir.path().to_path_buf(), directory()).with_quota_limit(0);
	session.command_line(&format!("a1 LOGIN alice {}", fixtures::password()));
	let quota = text(&session.command_line("a3 GETQUOTA \"\""));
	// RFC 9208: a root with no limited resource lists none.
	assert!(quota.contains("* QUOTA \"\" ()\r\n"), "{quota}");
}
