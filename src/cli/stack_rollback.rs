//! `epistle stack rollback`: put back the binary the last upgrade replaced
//! and, when the new server already migrated the schema, the database dump
//! `stack update` took before the restart.
//!
//! The preinst keeps the replaced `/usr/bin/epistle` under
//! `/var/lib/glyndor/epistle/rollback/epistle-<version>`. Root swaps the
//! binary; the database work runs as the service account through the hidden
//! `stack rollback-db`, because the stack is that account's rootless Podman.
//!
//! Limits, stated to the operator as well: dpkg still records the newer
//! version and the next upgrade replaces the binary again, and mail the new
//! version wrote to the database after the dump is lost when the dump is
//! restored (the message files on disk are kept).

use std::collections::BTreeSet;

/// Where the preinst keeps replaced binaries.
pub(super) const KEPT: &str = "/var/lib/glyndor/epistle/rollback";

/// The kept binary to go back to: `epistle-<to>` when `to` is given,
/// otherwise the highest version below `current`.
pub(super) fn pick(files: &[String], current: &str, to: Option<&str>) -> Result<String, String> {
	let kept: Vec<(&str, Vec<u64>)> = files
		.iter()
		.filter_map(|name| {
			let version = name.strip_prefix("epistle-")?;
			Some((version, numbers(version)?))
		})
		.collect();
	let listing = || {
		let mut versions: Vec<&str> = kept.iter().map(|(version, _)| *version).collect();
		versions.sort();
		versions.join(", ")
	};
	if let Some(to) = to {
		return kept
			.iter()
			.find(|(version, _)| *version == to)
			.map(|(version, _)| format!("epistle-{version}"))
			.ok_or_else(|| format!("{KEPT} has no epistle-{to}; it keeps: {}", listing()));
	}
	let current = numbers(current).unwrap_or_default();
	kept.iter()
		.filter(|(_, parsed)| *parsed < current)
		.max_by(|left, right| left.1.cmp(&right.1))
		.map(|(version, _)| format!("epistle-{version}"))
		.ok_or_else(|| {
			format!(
				"{KEPT} holds no earlier binary than this one (it keeps: {}); the preinst \
				 keeps one on each upgrade from this release on",
				listing()
			)
		})
}

/// `0.10.1` as `[0, 10, 1]`, `None` when a part is not a number.
fn numbers(version: &str) -> Option<Vec<u64>> {
	version.split('.').map(|part| part.parse().ok()).collect()
}

/// The migration versions a plain `pg_dump` recorded in `_sqlx_migrations`.
pub(super) fn migrations_in_dump(sql: &str) -> BTreeSet<i64> {
	let mut versions = BTreeSet::new();
	let mut inside = false;
	for line in sql.lines() {
		if inside {
			if line == "\\." {
				inside = false;
			} else if let Some(Ok(version)) = line.split('\t').next().map(str::parse) {
				versions.insert(version);
			}
		} else if line.starts_with("COPY public._sqlx_migrations ") && line.ends_with("FROM stdin;")
		{
			inside = true;
		}
	}
	versions
}

/// Whether the database ran a migration the dump does not have.
pub(super) fn schema_moved(dump: &BTreeSet<i64>, database: &BTreeSet<i64>) -> bool {
	!database.is_subset(dump)
}

/// The line `stack rollback-db` prints on stdout when it restored the dump;
/// the root half reads it to say what happened to the database.
pub(super) const RESTORED: &str = "database=restored";

/// The question `stack rollback` asks before it changes anything.
pub(super) fn question(current: &str, version: &str) -> String {
	format!(
		"Replace /usr/bin/epistle {current} with {version} and, if {current} already migrated \
		 the database, restore the dump taken before the upgrade? [y/N]"
	)
}

/// Ask [`question`] on `console`, or take `--yes`: the convention of the
/// other destructive commands (exit 2 when not confirmed). The command runs
/// the same check on the process's terminal through `confirm_destructive`.
#[cfg(test)]
pub(super) fn confirm(
	console: &mut crate::cli::prompt::Console<'_>,
	current: &str,
	version: &str,
	yes: bool,
) -> Result<(), std::process::ExitCode> {
	crate::cli::prompt::confirm_with(console, &action(version), &question(current, version), yes)
}

/// The action the prompt and its refusal name.
pub(super) fn action(version: &str) -> String {
	format!("stack rollback to {version}")
}

/// Whether the database half reported restoring the dump.
pub(super) fn restored(stdout: &str) -> bool {
	stdout.lines().any(|line| line.trim() == RESTORED)
}

/// The closing message, which names the lost database changes only when
/// the dump was restored.
pub(super) fn summary(current: &str, version: &str, restored: bool) -> String {
	let database = if restored {
		"The database is back to the dump taken before the upgrade, so whatever it took \
		 after that (accounts, flags, queue state) is gone from the database; the message \
		 files stay on disk."
	} else {
		"The database was kept as it was: the schema had not moved past the dump."
	};
	format!(
		"/usr/bin/epistle is the {version} binary again and mail was started on it; check it \
		 with `sudo epistle status`. {database} dpkg still lists {current} as installed, so the \
		 next apt upgrade replaces the binary again: hold the package with `sudo apt-mark hold \
		 epistle` until a fixed release."
	)
}

#[path = "stack_rollback_run.rs"]
mod run;
pub(super) use run::{restore_db, run_as_root};

#[cfg(test)]
#[path = "stack_rollback_tests.rs"]
mod tests;
