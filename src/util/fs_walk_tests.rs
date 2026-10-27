use std::path::Path;

use super::{skipped_notice, warn_skipped};

#[test]
fn skipped_notice_names_the_path_with_the_account_pseudonymised() {
	let notice = skipped_notice(Path::new("/var/lib/epistle/accounts/alice/new/x.eml"));
	let id = crate::log_id::account("alice");
	assert_eq!(
		notice,
		format!("skipping non-regular data path /var/lib/epistle/accounts/{id}/new/x.eml")
	);
}

#[test]
fn the_logged_warning_does_not_carry_the_account_name() {
	let events = crate::cli::trace::capture::run_with_capture(|| {
		warn_skipped(Path::new("/var/lib/epistle/accounts/zelda/new/y.eml"));
	});
	assert_eq!(events.len(), 1, "one warning expected");
	let message = events[0].fields.get("message").expect("message field");
	assert!(
		message.contains(&crate::log_id::account("zelda")),
		"the warning must carry the account pseudonym"
	);
	assert!(
		!message.contains("zelda"),
		"the warning must not carry the account name"
	);
}
