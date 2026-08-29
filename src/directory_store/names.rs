//! What an account may be called, and what happens to a directory row that
//! breaks the rule.
//!
//! The name doubles as a directory under `<data_dir>/accounts/`, so this is
//! the boundary between a directory backend and the filesystem.

use super::StoreError;

/// Drop the accounts an external directory named unsafely, logging each one.
///
/// An account name doubles as a directory name under `<data_dir>/accounts/`,
/// and `mailbox_dir` joins it without checking: it validates the *mailbox*
/// name and trusts the account. Config accounts are checked by
/// `Config::validate_accounts` and API/SCIM accounts by `add`, but SQL and
/// LDAP rows went straight into the store, so a directory that returned
/// `../..` reached the filesystem through the authenticated session.
///
/// Rejected rows are dropped rather than failing the whole refresh: these
/// sources are reloaded on a timer, and one malformed row must not take the
/// entire directory offline. It must not reach a path either.
pub(super) fn with_safe_names<T>(
	accounts: Vec<T>,
	source: &str,
	name_of: impl Fn(&T) -> &str,
) -> Vec<T> {
	accounts
		.into_iter()
		.filter(|account| {
			let name = name_of(account);
			match validate_name(name) {
				Ok(()) => true,
				Err(error) => {
					tracing::warn!(
						source,
						%error,
						"ignoring a directory account whose name cannot be a directory name",
					);
					false
				}
			}
		})
		.collect()
}

pub(super) fn validate_name(name: &str) -> Result<(), StoreError> {
	let safe = !name.is_empty()
		&& name.len() <= 64
		&& name
			.chars()
			.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
		&& !name.starts_with('-');
	if safe {
		Ok(())
	} else {
		Err(StoreError::Invalid(format!(
			"account name \"{name}\" must be lowercase alphanumeric/hyphen"
		)))
	}
}
