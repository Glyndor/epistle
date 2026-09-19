use super::*;

#[test]
fn concurrent_appends_keep_every_record_on_its_own_line() {
	let dir = tempfile::tempdir().expect("tempdir");
	let barrier = std::sync::Barrier::new(8);
	std::thread::scope(|scope| {
		for writer in 0..8 {
			let dir = dir.path();
			let barrier = &barrier;
			scope.spawn(move || {
				barrier.wait();
				for record in 0..200 {
					append(
						dir,
						Kind::Dmarc,
						"20240101",
						"org",
						&serde_json::json!({"id": writer * 200 + record}),
					)
					.expect("append");
				}
			});
		}
	});
	let bytes = std::fs::read_to_string(dir.path().join("reports/dmarc/20240101/org.jsonl"))
		.expect("read JSONL");
	let mut ids = std::collections::BTreeSet::new();
	for line in bytes.lines() {
		let value: serde_json::Value =
			serde_json::from_str(line).expect("one JSON object per line");
		assert!(
			ids.insert(value["id"].as_u64().expect("record id")),
			"duplicate record"
		);
	}
	assert!(bytes.ends_with('\n'));
	assert_eq!(ids, (0..1600).collect());
}

#[cfg(unix)]
#[test]
fn append_writes_the_jsonl_at_0600_and_directories_at_0700() {
	use std::os::unix::fs::PermissionsExt;
	let dir = tempfile::tempdir().expect("tempdir");
	let report = serde_json::json!({ "ok": true });
	append(dir.path(), Kind::Dmarc, "20240101", "google.com", &report).expect("append");
	let day_dir = dir.path().join("reports").join("dmarc").join("20240101");
	let jsonl = day_dir.join("google.com.jsonl");
	let jsonl_mode = std::fs::metadata(&jsonl)
		.expect("stat")
		.permissions()
		.mode();
	assert_eq!(
		jsonl_mode & 0o777,
		0o600,
		"jsonl must be 0600, got {:o}",
		jsonl_mode & 0o777
	);
	for sub in [
		day_dir.as_path(),
		dir.path().join("reports").join("dmarc").as_path(),
		dir.path().join("reports").as_path(),
	] {
		let mode = std::fs::metadata(sub).expect("stat").permissions().mode();
		assert_eq!(
			mode & 0o777,
			0o700,
			"{} must be 0700, got {:o}",
			sub.display(),
			mode & 0o777
		);
	}
}

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
