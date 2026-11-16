//! The user drop-in: written and removed by the account.

use std::path::Path;

use super::{Change, Host, RESTART_FROM, Scope, sync, user_text};
use crate::config::Boot;

/// What [`ensure_user`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::cli) enum Outcome {
	/// The drop-in is as the configuration says.
	Done(Change),
	/// The systemd of this host is older than 244, which refuses a `oneshot`
	/// unit with `Restart=`; the drop-in was not written.
	TooOld(u32),
}

/// Leave the user drop-in at `path` as `boot` says: written when
/// `restart_on_failure` is on and systemd is 244 or later, removed when the
/// switch is off. It runs no unit and changes no container.
pub(in crate::cli) fn ensure_user(
	host: &mut impl Host,
	path: &Path,
	boot: &Boot,
) -> Result<Outcome, String> {
	if !boot.restart_on_failure {
		return sync(host, Scope::User, path, None).map(Outcome::Done);
	}
	let version = host
		.systemd_version()
		.ok_or_else(|| "cannot read the systemd version".to_string())?;
	if version < RESTART_FROM {
		return Ok(Outcome::TooOld(version));
	}
	sync(host, Scope::User, path, Some(&user_text())).map(Outcome::Done)
}

/// Remove the user drop-in at `path`: `stack down` leaves no unit, so no
/// drop-in either.
pub(in crate::cli) fn remove_user(host: &mut impl Host, path: &Path) -> Result<Change, String> {
	sync(host, Scope::User, path, None)
}
