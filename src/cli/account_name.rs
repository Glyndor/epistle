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
/// when it differs from what was typed, so the operator knows which name
/// to use from now on.
pub(crate) fn for_new_account(typed: &str) -> String {
	let stored = account_name(typed);
	if stored != typed {
		eprintln!("note: account name \"{typed}\" is stored as \"{stored}\"");
	}
	stored
}
