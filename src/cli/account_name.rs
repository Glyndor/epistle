//! Account-name arguments on the command line.
//!
//! An account identifier is stored in lowercase (it doubles as the mailbox
//! directory name), so every argument that names an account is read in that
//! form: `account show Alice` finds `alice`. Whether the name is acceptable
//! is still decided by the store.

use crate::directory_store::account_name;

/// Clap value parser for an argument naming an existing account.
pub(crate) fn parse(raw: &str) -> Result<String, String> {
	Ok(account_name(raw))
}

/// The stored form of a name typed for a new account, with a note on stderr
/// when it differs from what was typed, so the operator knows to use the
/// stored form from now on. The note repeats neither name: an account name
/// is personal data, and stderr often ends up in a log.
pub(crate) fn for_new_account(typed: &str) -> String {
	let stored = account_name(typed);
	if stored != typed {
		eprintln!(
			"note: the account name is stored in lowercase without surrounding spaces; \
			 use that form from now on"
		);
	}
	stored
}
