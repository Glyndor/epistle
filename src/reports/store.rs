//! Persist ingested reports as JSONL and prune old days.
//!
//! Layout under `data_dir`:
//!
//! ```text
//! reports/
//!   dmarc/{YYYYMMDD}/{org}.jsonl
//!   tlsrpt/{YYYYMMDD}/{org}.jsonl
//! ```
//!
//! One JSON object per line. The directory is created on demand; missing
//! parent dirs are tolerated and created. The org name is the sanitised
//! `organization-name` / `org_name` from the parsed document, so a slash
//! in an org name still produces a single-segment filename.
//!
//! [`prune`] drops day directories whose `YYYYMMDD` is older than
//! `days`. The hourly storage-maintenance task in `serve_tasks.rs` calls
//! it with the retention constant from `crate::reports::RETENTION_DAYS`.

use std::path::Path;

/// Remove day directories older than `days` under both report buckets.
/// `today` is the current `YYYYMMDD` string. Days are whole days; a day
/// directory is removed when `today - directory > days`.
pub fn prune(data_dir: &Path, today: &str, days: u32) {
	for bucket in ["dmarc", "tlsrpt"] {
		let root = data_dir.join("reports").join(bucket);
		let Ok(entries) = std::fs::read_dir(&root) else {
			continue;
		};
		for entry in entries.flatten() {
			let day = match entry.file_name().into_string() {
				Ok(s) if s.len() == 8 && s.chars().all(|c| c.is_ascii_digit()) => s,
				_ => continue,
			};
			if day_diff(today, &day) > days as i64 {
				let _ = std::fs::remove_dir_all(entry.path());
			}
		}
	}
}

/// Number of days `day` is before `today`, clamped at 0 when `day` is
/// not a valid `YYYYMMDD`. We compute it via Unix seconds so the
/// arithmetic survives month and year boundaries.
fn day_diff(today: &str, day: &str) -> i64 {
	let (Some(t), Some(d)) = (ymd_to_unix(today), ymd_to_unix(day)) else {
		return 0;
	};
	((t - d) / 86_400).max(0)
}

fn ymd_to_unix(s: &str) -> Option<i64> {
	if s.len() != 8 || !s.chars().all(|c| c.is_ascii_digit()) {
		return None;
	}
	let y: i64 = s[..4].parse().ok()?;
	let m: i64 = s[4..6].parse().ok()?;
	let d: i64 = s[6..8].parse().ok()?;
	let (y, m) = if m <= 2 { (y - 1, m + 9) } else { (y, m - 3) };
	let era = y.div_euclid(400);
	let yoe = y - era * 400;
	let doy = (153 * m + 2) / 5 + d - 1;
	let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
	Some((era * 146097 + doe - 719468) * 86_400)
}

#[cfg(test)]
mod tests {
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

		// 4-day window: only 2024-01-05 and earlier are older than
		// (today - 4 = 2024-01-06). Wait, that's 1 and 5 are older,
		// 20240109 is within window.
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
}
