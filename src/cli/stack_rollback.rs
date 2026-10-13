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

#[path = "stack_rollback_run.rs"]
mod run;
pub(super) use run::{restore_db, run_as_root};

#[cfg(test)]
#[path = "stack_rollback_tests.rs"]
mod tests;
