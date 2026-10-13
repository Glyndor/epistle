//! The database dumps the stack takes for itself before a change it cannot
//! undo without them: `stack update` before the new server migrates the
//! schema, `db upgrade` before the new major takes over. They live under
//! `data_dir/backups` as `<name>-<UTC timestamp>.sql.gz`, mode 0600 (a dump
//! holds password hashes and keys), and only the newest few are kept.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// How many `pre-*` dumps are kept; older ones are deleted.
pub(super) const KEEP: usize = 3;

/// The directory the dumps live in.
pub(super) fn dir(data_dir: &Path) -> PathBuf {
	data_dir.join("backups")
}

/// Write `sql` gzipped as `<name>-<timestamp>.sql.gz` and delete all but
/// the newest [`KEEP`] `pre-*` dumps. Returns the path written.
pub(super) fn keep(
	data_dir: &Path,
	name: &str,
	sql: &[u8],
	now: SystemTime,
) -> std::io::Result<PathBuf> {
	let dir = dir(data_dir);
	std::fs::create_dir_all(&dir)?;
	let path = dir.join(format!("{name}-{}.sql.gz", stamp(now)));
	let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
	encoder.write_all(sql)?;
	crate::storage::write_secret(&path, &encoder.finish()?)?;
	prune(&dir, KEEP)?;
	Ok(path)
}

/// Delete all but the newest `keep` `pre-*.sql.gz` files in `dir`. The
/// timestamp in the name sorts as text in time order.
pub(super) fn prune(dir: &Path, keep: usize) -> std::io::Result<()> {
	let mut dumps = listed(dir, "pre-")?;
	while dumps.len() > keep {
		std::fs::remove_file(dumps.remove(0))?;
	}
	Ok(())
}

/// The `.sql.gz` files in `dir` whose name starts with `prefix`, oldest
/// first by the timestamp at the end of the name.
fn listed(dir: &Path, prefix: &str) -> std::io::Result<Vec<PathBuf>> {
	let mut found: Vec<(String, PathBuf)> = Vec::new();
	for entry in std::fs::read_dir(dir)? {
		let path = entry?.path();
		let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
			continue;
		};
		if let Some(stem) = name.strip_suffix(".sql.gz")
			&& name.starts_with(prefix)
		{
			let stamp = stem.rsplit('-').next().unwrap_or_default().to_string();
			found.push((stamp, path));
		}
	}
	found.sort();
	Ok(found.into_iter().map(|(_, path)| path).collect())
}

/// `YYYYMMDDTHHMMSSZ` for `now`, in UTC.
fn stamp(now: SystemTime) -> String {
	let secs = now
		.duration_since(SystemTime::UNIX_EPOCH)
		.map(|elapsed| elapsed.as_secs() as i64)
		.unwrap_or(0);
	let (year, month, day) = crate::webdav::rrule::civil_from_secs(secs);
	let of_day = secs.rem_euclid(86_400);
	format!(
		"{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
		of_day / 3600,
		of_day % 3600 / 60,
		of_day % 60
	)
}

#[cfg(test)]
#[path = "stack_dumps_tests.rs"]
mod tests;
