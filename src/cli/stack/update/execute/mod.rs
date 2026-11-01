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
	/// Delete the `pre-<version>-*` dumps once the update is verified;
	/// returns how many went.
	fn discard_dumps(&mut self) -> Result<usize, String>;
	/// Take the superuser attribute away from the `epistle` role when an
	/// older install still has it; `true` when it did.
	fn harden_database(&mut self) -> Result<bool, String>;
	/// Move the keys the compose file mounts out of data_dir and create
	/// any that are missing; one line per thing done.
	fn prepare_keys(&mut self) -> Result<Vec<String>, String>;
	/// Replace the compose file atomically.
	fn write_compose(&mut self, text: &str) -> Result<(), String>;
	/// Run one podup step.
	fn podup(&mut self, step: &[String]) -> Result<(), String>;
	/// Wait until `service` reports healthy.
	fn wait_healthy(&mut self, service: &str) -> Result<(), String>;
	/// The `status` areas a restart can break that now fail, with their
	/// detail.
	fn failing_areas(&mut self) -> Vec<(String, String)>;
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
	// The compose file mounts the keys from outside data_dir, so they have
	// to be there before podup reads it.
	for line in host.prepare_keys()? {
		host.log(&line);
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
	// Only now is `db` running with the admin secret mounted. Mail's open
	// sessions keep the renamed role's superuser until it reconnects.
	if host.has_database()
		&& host
			.harden_database()
			.map_err(|error| format!("{error}. {ROLLBACK}"))?
	{
		host.log("the epistle role no longer has SUPERUSER; epistle_admin holds it");
		host.podup(&["restart".to_string(), "mail".to_string()])?;
	}
	host.wait_healthy("mail")
		.map_err(|error| format!("{error}. {ROLLBACK}"))?;
	let failing = host.failing_areas();
	if !failing.is_empty() {
		let named: Vec<String> = failing
			.iter()
			.map(|(area, detail)| format!("{area}: {detail}"))
			.collect();
		return Err(format!(
			"mail restarted but status fails ({}). {ROLLBACK}",
			named.join("; ")
		));
	}
	host.log("mail is healthy and config, ports and db pass");
	// The dumps only exist so `stack rollback` can put the schema back; a
	// verified update has nothing to go back from. A failure here is a
	// leftover, not a failed update.
	if host.has_database() {
		match host.discard_dumps() {
			Ok(0) => {}
			Ok(count) => host.log(&format!(
				"removed {count} dump(s) taken before the update, which came back healthy"
			)),
			Err(error) => host.log(&format!(
				"could not remove the dumps taken before the update: {error}"
			)),
		}
	}
	Ok(())
}

/// What a failed restart tells the operator to run.
const ROLLBACK: &str = "To go back to the previous version and, if the schema moved, the \
	database from before the update, run `sudo epistle stack rollback`";

#[cfg(test)]
mod tests;
