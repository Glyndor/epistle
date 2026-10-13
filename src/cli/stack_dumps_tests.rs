//! Tests for the stack's own dumps.

use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, SystemTime};

use super::{KEEP, keep};

fn at(secs: u64) -> SystemTime {
	SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
}

#[test]
fn a_dump_is_gzipped_private_and_named_by_utc_time() {
	let dir = tempfile::tempdir().unwrap();
	let path = keep(dir.path(), "pre-0.12.0", b"-- sql", at(1_760_000_000)).unwrap();
	assert_eq!(
		path.file_name().unwrap(),
		"pre-0.12.0-20251009T085320Z.sql.gz"
	);
	assert_eq!(
		std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
		0o600
	);
	let mut text = String::new();
	flate2::read::GzDecoder::new(std::fs::File::open(&path).unwrap())
		.read_to_string(&mut text)
		.unwrap();
	assert_eq!(text, "-- sql");
}

#[test]
fn only_the_newest_pre_dumps_are_kept() {
	let dir = tempfile::tempdir().unwrap();
	let backups = dir.path().join("backups");
	std::fs::create_dir_all(&backups).unwrap();
	std::fs::write(backups.join("nightly.tar.gz"), "operator's").unwrap();
	// Oldest first in time; the names sort in a different order, so only a
	// prune by the timestamp keeps the right three.
	for (index, name) in [
		"pre-db-upgrade-17-to-18",
		"pre-0.10.1",
		"pre-0.11.0",
		"pre-0.12.0",
		"pre-0.12.1",
	]
	.iter()
	.enumerate()
	{
		keep(dir.path(), name, b"x", at(1_760_000_000 + index as u64)).unwrap();
	}
	let mut left: Vec<String> = std::fs::read_dir(&backups)
		.unwrap()
		.map(|entry| entry.unwrap().file_name().into_string().unwrap())
		.collect();
	left.sort();
	assert_eq!(left.len(), KEEP + 1, "{left:?}");
	assert!(
		left.contains(&"nightly.tar.gz".to_string()),
		"other files are never pruned"
	);
	assert!(left.iter().any(|name| name.starts_with("pre-0.12.1-")));
	assert!(
		!left.iter().any(|name| name.starts_with("pre-0.10.1-")),
		"{left:?}"
	);
	assert!(
		!left.iter().any(|name| name.starts_with("pre-db-")),
		"{left:?}"
	);
}
