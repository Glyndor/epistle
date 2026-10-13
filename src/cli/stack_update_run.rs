//! Carrying out a planned `stack update` against an [`UpdateHost`] the
//! tests can fake: the pre-migration dump, the new compose file and the
//! podup steps.

use std::path::PathBuf;

use super::UpdatePlan;

/// What carrying out an update needs from the host.
pub(super) trait UpdateHost {
	/// Whether the stack runs its own PostgreSQL (a `db` service).
	fn has_database(&self) -> bool;
	/// A plain SQL dump of the stack's database.
	fn dump(&mut self) -> Result<Vec<u8>, String>;
	/// Keep the dump as `pre-<version>-<timestamp>.sql.gz` under
	/// `data_dir/backups`, pruning older ones.
	fn keep_dump(&mut self, sql: &[u8]) -> Result<PathBuf, String>;
	/// Replace the compose file atomically.
	fn write_compose(&mut self, text: &str) -> Result<(), String>;
	/// Run one podup step.
	fn podup(&mut self, step: &[String]) -> Result<(), String>;
	/// Report a line to the operator.
	fn log(&mut self, line: &str);
}

/// Carry out `plan`. `Err` says what failed and what was already changed.
pub(super) fn execute(host: &mut impl UpdateHost, plan: &UpdatePlan) -> Result<(), String> {
	for note in &plan.notes {
		host.log(note);
	}
	// The new server migrates the schema when it starts, and an older
	// binary cannot read a migrated schema. Without a dump taken before
	// that, `stack rollback` would have nothing to put back.
	if host.has_database() {
		let saved = host
			.dump()
			.and_then(|sql| host.keep_dump(&sql))
			.map_err(|error| {
				format!("cannot take the dump before the restart ({error}); nothing was changed")
			})?;
		host.log(&format!(
			"database dumped to {} before the restart",
			saved.display()
		));
	}
	if let Some(text) = &plan.rewrite {
		host.log("compose.yaml changes:");
		for line in &plan.diff {
			host.log(&format!("  {line}"));
		}
		host.write_compose(text)?;
	} else {
		host.log("compose.yaml is current");
	}
	for step in &plan.steps {
		host.podup(&step.0)?;
	}
	Ok(())
}

#[cfg(test)]
#[path = "stack_update_run_tests.rs"]
mod tests;
