use super::*;

#[test]
fn day_diff_handles_year_and_month_boundaries() {
	// 2024 is a leap year.
	assert_eq!(day_diff("20240301", "20240228"), 2);
	assert_eq!(day_diff("20240101", "20231231"), 1);
	assert_eq!(day_diff("20240110", "20240105"), 5);
}

#[test]
fn prune_drops_days_older_than_window_and_keeps_recent() {
	let dir = tempfile::tempdir().expect("tempdir");
	let today = "20240110";
	// Two old, one recent.
	for day in ["20240101", "20240105", "20240109"] {
		let path = dir.path().join("reports").join("dmarc").join(day);
		std::fs::create_dir_all(&path).expect("mkdir");
		std::fs::write(path.join("example.jsonl"), b"old line\n").expect("write");
	}
	// Also keep a file at root level for `tlsrpt`.
	let tls_root = dir.path().join("reports").join("tlsrpt");
	std::fs::create_dir_all(&tls_root).expect("mkdir");
	let path = tls_root.join("20240101");
	std::fs::create_dir_all(&path).expect("mkdir");
	std::fs::write(path.join("example.jsonl"), b"old line\n").expect("write");

	// A 4 day window from 2024-01-10 keeps 2024-01-06 onwards: the 1st and
	// the 5th go, the 9th stays.
	prune(dir.path(), today, 4);

	assert!(
		!dir.path()
			.join("reports")
			.join("dmarc")
			.join("20240101")
			.exists()
	);
	assert!(
		!dir.path()
			.join("reports")
			.join("dmarc")
			.join("20240105")
			.exists()
	);
	assert!(
		dir.path()
			.join("reports")
			.join("dmarc")
			.join("20240109")
			.exists()
	);
	assert!(
		!dir.path()
			.join("reports")
			.join("tlsrpt")
			.join("20240101")
			.exists()
	);
}

#[test]
fn prune_is_safe_when_no_reports_directory() {
	let dir = tempfile::tempdir().expect("tempdir");
	prune(dir.path(), "20240110", 90);
}
