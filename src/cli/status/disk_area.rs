//! The `disk` check: free space on the filesystem holding `data_dir`.
//!
//! Measured with the same `statvfs` probe the SMTP disk guard polls
//! (`smtp::diskspace`). That guard only knows an absolute floor (one maximum
//! message), so the percentage thresholds live here, and the guard's floor is
//! reported as its own finding: under it the server answers 452 and refuses
//! new mail.

use std::path::Path;

use super::Ctx;
use super::report::{AreaReport, Item, Level};
use crate::smtp::diskspace::usage;
use crate::smtp::session::MAX_MESSAGE_SIZE;

/// Free space below this percentage of the filesystem: warn.
const WARN_PERCENT: u128 = 10;

/// Free space below this percentage of the filesystem: fail.
const FAIL_PERCENT: u128 = 5;

/// Check the data filesystem.
pub(super) async fn check(ctx: &Ctx) -> AreaReport {
	let config = match ctx.loaded() {
		Ok(config) => config,
		Err(report) => return report,
	};
	let data_dir = config.data_dir.clone();
	let reading = tokio::task::spawn_blocking(move || measure(&data_dir))
		.await
		.unwrap_or(None);
	evaluate(reading)
}

/// Free and total bytes of the filesystem that holds `path`, or of its
/// nearest existing parent when the directory is not created yet.
fn measure(path: &Path) -> Option<(u64, u64)> {
	path.ancestors()
		.find(|candidate| candidate.exists())
		.and_then(usage)
}

/// Judge a free/total reading (bytes).
fn evaluate(reading: Option<(u64, u64)>) -> AreaReport {
	let Some((available, total)) = reading.filter(|(_, total)| *total > 0) else {
		return AreaReport::single(Level::Warn, "cannot read the filesystem's free space");
	};
	let free_x100 = u128::from(available) * 100;
	let level = if free_x100 < u128::from(total) * FAIL_PERCENT {
		Level::Fail
	} else if free_x100 < u128::from(total) * WARN_PERCENT {
		Level::Warn
	} else {
		Level::Ok
	};
	let percent = free_x100 / u128::from(total);
	let detail = format!("{percent}% free ({} of {})", size(available), size(total));
	let mut items = vec![Item::new("free space", level, detail.clone())];
	let floor = MAX_MESSAGE_SIZE as u64;
	if available < floor {
		items.push(Item::new(
			"smtp",
			Level::Fail,
			format!(
				"under {} free: SMTP answers 452 and refuses new mail",
				size(floor)
			),
		));
	}
	AreaReport::from_items(items, detail)
}

/// Bytes as GiB, or MiB below one GiB.
fn size(bytes: u64) -> String {
	const MIB: f64 = 1024.0 * 1024.0;
	let mib = bytes as f64 / MIB;
	if mib >= 1024.0 {
		format!("{:.1} GiB", mib / 1024.0)
	} else {
		format!("{mib:.1} MiB")
	}
}

#[cfg(test)]
#[path = "disk_area_tests.rs"]
mod tests;
