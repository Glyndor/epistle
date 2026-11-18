//! The steps of `epistle db upgrade`, against a [`Stack`] the tests can fake.
//!
//! The PostgreSQL images from 18 on keep each major's cluster in its own
//! directory of the volume (`PGDATA=/var/lib/postgresql/18/docker` was
//! measured on `postgres:18`). Their entrypoint also refuses to initialise a
//! new major at its default `PGDATA` while another major's cluster sits at
//! `/var/lib/postgresql/*/docker`: `postgres:19rc2` did so beside an 18
//! cluster on 2026-11-13, so with the stock images the move stops at the
//! `db` health check and the old major comes back. The old cluster, the dump
//! and the old image stay while the move can still fail, and go once `mail`
//! is healthy and the `config`, `ports` and `db` checks pass on the new major.

use std::path::{Path, PathBuf};

use crate::cli::init::images::major;
use crate::cli::stack::images::{Change, Outcome};

mod leftovers;

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
	/// Where the running server keeps its cluster (`SHOW data_directory`).
	fn data_directory(&mut self) -> Result<String, String>;
	/// The `config`, `ports` and `db` status areas that now fail, with
	/// their detail.
	fn failing_checks(&mut self) -> Vec<(String, String)>;
	/// Remove `path` inside the `db` container: with its tree when `tree`,
	/// otherwise only when it is an empty directory.
	fn remove_in_db(&mut self, path: &str, tree: bool) -> Result<(), String>;
	/// Delete the dump [`Stack::keep_dump`] wrote at `path`.
	fn remove_dump(&mut self, path: &Path) -> Result<(), String>;
	/// Remove the images `change` retired that nothing uses.
	fn discard_images(&mut self, change: &Change) -> Result<Outcome, String>;
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
	// Asked of the old server while it runs: the directory a verified move
	// removes is the one it reported, never one derived from its major.
	let old_dir = stack.data_directory()?;
	let upgraded = compose.replace(&format!("\"{running}\""), &format!("\"{target}\""));
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
		stack.write_compose(&upgraded)?;
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
			if let Err(why) = verify(stack) {
				return Err(format!(
					"the database runs on PostgreSQL {to} with every table's row count unchanged, \
					 but {why}. Nothing of PostgreSQL {from} was removed: its cluster stays at \
					 {old_dir} in the epistle-pgdata volume, its image in the storage and the dump \
					 at {}",
					saved.display()
				));
			}
			stack.log(&format!(
				"the database runs on PostgreSQL {to} with every table's row count unchanged, mail \
				 is healthy and config, ports, db pass"
			));
			let change = serde_json::from_str(&upgraded)
				.map(|new| crate::cli::stack::images::change(&document, &new))
				.unwrap_or_default();
			leftovers::discard(stack, from, &old_dir, &saved, &change);
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

/// Whether the stack came back healthy on the new major: `mail` reports
/// healthy and the `config`, `ports` and `db` checks pass, the same bar a
/// `stack update` has to clear. `Err` names what failed.
fn verify(stack: &mut impl Stack) -> Result<(), String> {
	stack
		.wait_healthy("mail")
		.map_err(|error| format!("mail did not come back healthy ({error})"))?;
	let failing = stack.failing_checks();
	if failing.is_empty() {
		return Ok(());
	}
	let named: Vec<String> = failing
		.iter()
		.map(|(area, detail)| format!("{area}: {detail}"))
		.collect();
	Err(format!("status fails ({})", named.join("; ")))
}

#[cfg(test)]
mod tests;
