//! The steps of `epistle db upgrade`, against a [`Stack`] the tests can fake.
//!
//! The PostgreSQL images from 18 on keep each major's cluster in its own
//! directory of the volume (`PGDATA=/var/lib/postgresql/18/docker` was
//! measured on `postgres:18`), so the new major initialises next to the old
//! cluster instead of over it. The old one stays on disk, untouched, until
//! the operator removes it.

use std::path::PathBuf;

use crate::cli::init::images::major;

/// What the upgrade needs from the stack. The real implementation drives
/// podup; the tests record the calls.
pub(crate) trait Stack {
	/// The current compose file.
	fn compose(&mut self) -> Result<String, String>;
	/// Replace the compose file atomically.
	fn write_compose(&mut self, text: &str) -> Result<(), String>;
	/// Run `podup -f <compose> <args>`.
	fn podup(&mut self, args: &[&str]) -> Result<(), String>;
	/// Wait until `service` reports healthy.
	fn wait_healthy(&mut self, service: &str) -> Result<(), String>;
	/// One line naming every table with its exact row count.
	fn counts(&mut self) -> Result<String, String>;
	/// A plain SQL dump of the database.
	fn dump(&mut self) -> Result<Vec<u8>, String>;
	/// Keep the dump under `data_dir/backups` as `<name>-<timestamp>.sql.gz`.
	fn keep_dump(&mut self, name: &str, sql: &[u8]) -> Result<PathBuf, String>;
	/// Load a dump into the running database, in one transaction.
	fn load(&mut self, sql: &[u8]) -> Result<(), String>;
	/// Report a step to the operator.
	fn log(&mut self, line: &str);
}

/// Move the stack's database to the major of `target`. Each step and the
/// closing summary go to the operator through [`Stack::log`]; `Err` says
/// what failed and that the old major is running again.
pub(crate) fn upgrade(stack: &mut impl Stack, target: &str) -> Result<(), String> {
	let compose = stack.compose()?;
	let document: serde_json::Value = serde_json::from_str(&compose)
		.map_err(|error| format!("compose.yaml is not the JSON epistle init writes: {error}"))?;
	let running = document["services"]["db"]["image"]
		.as_str()
		.ok_or("compose.yaml has no `db` service; the stack runs without PostgreSQL")?
		.to_string();
	let (Some(from), Some(to)) = (major(&running), major(target)) else {
		return Err(format!(
			"cannot read a PostgreSQL major from {running} or {target}"
		));
	};
	if from == to {
		stack.log(&format!(
			"the stack already runs PostgreSQL {to}; nothing to upgrade"
		));
		return Ok(());
	}
	if from > to {
		return Err(format!(
			"the stack runs PostgreSQL {from} and this release pins {to}; a dump does not go back to an older major"
		));
	}
	let before = stack.counts()?;
	stack.log(&format!(
		"moving the database from PostgreSQL {from} to {to}; mail is stopped meanwhile"
	));
	stack.podup(&["stop", "mail"])?;
	let mut swapped = false;
	let result = (|| -> Result<PathBuf, String> {
		let sql = stack.dump()?;
		let saved = stack.keep_dump(&format!("pre-db-upgrade-{from}-to-{to}"), &sql)?;
		stack.log(&format!("dump kept at {}", saved.display()));
		stack.podup(&["stop", "db"])?;
		swapped = true;
		stack
			.write_compose(&compose.replace(&format!("\"{running}\""), &format!("\"{target}\"")))?;
		stack.podup(&["up", "-d", "db"])?;
		stack.wait_healthy("db")?;
		stack.load(&sql)?;
		let after = stack.counts()?;
		if after != before {
			return Err(format!(
				"the row counts differ after the restore (before: {before}; after: {after})"
			));
		}
		Ok(saved)
	})();
	match result {
		Ok(saved) => {
			stack.podup(&["up", "-d"])?;
			stack.log(&format!(
				"the database runs on PostgreSQL {to} with every table's row count unchanged. The \
				 PostgreSQL {from} cluster is still in the epistle-pgdata volume at \
				 /var/lib/postgresql/{from}, and the dump at {}; remove them once mail is verified",
				saved.display()
			));
			Ok(())
		}
		Err(error) => {
			let back = (|| -> Result<(), String> {
				if swapped {
					let _ = stack.podup(&["stop", "db"]);
					stack.write_compose(&compose)?;
				}
				stack.podup(&["up", "-d"])
			})();
			match back {
				Ok(()) => Err(format!(
					"{error}; PostgreSQL {from} is running again on its own data"
				)),
				Err(back) => Err(format!(
					"{error}; putting PostgreSQL {from} back failed too ({back}); its data is untouched \
					 at /var/lib/postgresql/{from}, restore compose.yaml's db image to {running} and run \
					 `sudo epistle stack up`"
				)),
			}
		}
	}
}

#[cfg(test)]
mod tests;
