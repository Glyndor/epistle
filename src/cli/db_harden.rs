//! Taking SUPERUSER away from the `epistle` role of a stack whose
//! PostgreSQL was initialised with it, during `stack update`. The SQL and
//! why it renames rather than demotes are in `init::db_roles`.

use std::path::Path;
use std::process::Stdio;

use crate::cli::init::db_roles;

/// `Ok(true)` when `epistle` was a superuser and no longer is, `Ok(false)`
/// when it already was not. The stack must be running the compose file
/// that mounts the admin secret into `db`.
pub(super) fn run(compose: &Path) -> Result<bool, String> {
	if super::db_upgrade::query(compose, db_roles::IS_SUPERUSER)? != "t" {
		return Ok(false);
	}
	let output = super::stack::build_command(
		"podup",
		compose,
		&["exec", "-T", "db", "sh", "-c", db_roles::HARDEN_SCRIPT],
	)
	.stdin(Stdio::null())
	.output()
	.map_err(|error| format!("cannot run podup exec: {error}"))?;
	if !output.status.success() {
		return Err(format!(
			"taking SUPERUSER away from the epistle role failed ({}): {}; the role kept it, \
			 and `sudo epistle stack update` tries again",
			output.status,
			String::from_utf8_lossy(&output.stderr).trim()
		));
	}
	match super::db_upgrade::query(compose, db_roles::IS_SUPERUSER)?.as_str() {
		"f" => Ok(true),
		other => Err(format!(
			"the epistle role still reports rolsuper = {other:?} after the change"
		)),
	}
}
