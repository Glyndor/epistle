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

use std::io::Write;
use std::path::Path;

use super::Kind;

/// Append `report` as one JSON line to
/// `{data_dir}/reports/{kind}/{day}/{org}.jsonl`. `org` must come from
/// [`super::bounds::file_component`], which is what keeps the path inside
/// the day directory. Directories are created on demand.
pub fn append(
	data_dir: &Path,
	kind: Kind,
	day: &str,
	org: &str,
	report: &impl serde::Serialize,
) -> std::io::Result<()> {
	let dir = data_dir.join("reports").join(kind.dir_name()).join(day);
	std::fs::create_dir_all(&dir)?;
	let path = dir.join(format!("{org}.jsonl"));
	let line = serde_json::to_string(report)
		.map_err(|e| std::io::Error::other(format!("serialize report: {e}")))?;
	let mut file = std::fs::OpenOptions::new()
		.create(true)
		.append(true)
		.open(&path)?;
	writeln!(file, "{line}")
}

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
#[path = "store_tests.rs"]
mod tests;
