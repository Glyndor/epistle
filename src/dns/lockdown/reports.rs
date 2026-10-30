//! The DMARC aggregate reports epistle has received, read for the
//! lockdown's warning before a policy step: which sending sources failed
//! DMARC for the domain lately. The reports live as JSON lines under
//! `<data_dir>/reports/dmarc/<YYYYMMDD>/<org>.jsonl`
//! ([`crate::reports::dmarc::append`]).

use std::collections::BTreeMap;
use std::path::Path;

use super::{FailingSource, canonical_name};
use crate::reports::dmarc::DmarcReport;

/// How many days of reports the warning covers.
pub const REPORT_WINDOW_DAYS: u64 = 30;

/// The sources that failed DMARC for `domain` in the reports of the last
/// [`REPORT_WINDOW_DAYS`] days before `now` (Unix seconds), with the
/// number of failing messages, most messages first; and whether any report
/// for `domain` was found at all. A report counts for `domain` when its
/// published policy names it; a row fails when the receiver quarantined or
/// rejected it, or when both DKIM and SPF failed. Unreadable files and
/// lines are skipped: the reports only feed a warning.
pub fn recent_dmarc_failures(
	data_dir: &Path,
	domain: &str,
	now: u64,
) -> (Vec<FailingSource>, bool) {
	let _warnings = crate::util::fs_walk::warning_scope();
	let oldest =
		crate::dmarc::aggregate::unix_to_day(now.saturating_sub(REPORT_WINDOW_DAYS * 86_400));
	let root = data_dir.join("reports").join("dmarc");
	let mut failing: BTreeMap<String, u64> = BTreeMap::new();
	let mut seen = false;
	let Ok(days) = crate::util::fs_walk::read_dir(&root) else {
		return (Vec::new(), false);
	};
	for day in days.flatten() {
		let Ok(name) = day.file_name().into_string() else {
			continue;
		};
		if name.len() != 8 || !name.bytes().all(|b| b.is_ascii_digit()) || name < oldest {
			continue;
		}
		let Ok(files) = crate::util::fs_walk::read_dir(day.path()) else {
			continue;
		};
		for file in files.flatten() {
			let path = file.path();
			if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
				continue;
			}
			let Ok(text) = crate::util::fs_walk::read_to_string(&path) else {
				continue;
			};
			for line in text.lines().filter(|l| !l.trim().is_empty()) {
				let Ok(report) = serde_json::from_str::<DmarcReport>(line) else {
					continue;
				};
				if canonical_name(&report.policy_published.domain) != domain {
					continue;
				}
				seen = true;
				for row in report
					.records
					.iter()
					.filter(|row| crate::reports::dmarc::is_failing(row))
				{
					if !row.source_ip.is_empty() {
						let total = failing.entry(row.source_ip.clone()).or_default();
						*total = total.saturating_add(row.count);
					}
				}
			}
		}
	}
	let mut sources: Vec<FailingSource> = failing
		.into_iter()
		.map(|(source_ip, messages)| FailingSource {
			source_ip,
			messages,
		})
		.collect();
	sources.sort_by(|a, b| {
		b.messages
			.cmp(&a.messages)
			.then(a.source_ip.cmp(&b.source_ip))
	});
	(sources, seen)
}
