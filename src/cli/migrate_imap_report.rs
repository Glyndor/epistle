//! What `epistle migrate imap` shows while it runs and when it ends.
//!
//! On a terminal each folder is a spinner row that ends as
//! ` ✔ INBOX into INBOX  1,204 messages, 88.1 MB, 4.2 MB/s  21s`. Off a
//! terminal the same facts are one plain line per folder on stderr. With
//! `--json` nothing is drawn: the summary on stdout is the output.

use std::io::Write;

use crate::cli::style;
use crate::cli::term::live::{Mark, Steps, row};
use crate::migrate::imap::{FolderReport, MigrateError, Progress, Skipped, Summary};

/// The live rows of one run.
pub(super) struct Live {
	steps: Steps,
	quiet: bool,
	dry_run: bool,
}

impl Live {
	/// Rows on stderr when it is decorated; nothing with `--json`.
	pub(super) fn start(json: bool, dry_run: bool) -> Self {
		Live {
			steps: Steps::start(&[], json),
			quiet: json,
			dry_run,
		}
	}

	/// End the run with a total row or line.
	pub(super) fn finish(mut self, summary: &Summary, error: Option<&MigrateError>) {
		// A run that failed before any folder has no total worth printing:
		// the error says it all.
		if self.quiet || self.dry_run || (error.is_some() && summary.folders.is_empty()) {
			return;
		}
		let line = format!(
			"copied {} {}, {} from {} {}",
			summary.copied,
			plural(summary.copied, "message"),
			bytes(summary.bytes),
			summary.folders.len(),
			plural(summary.folders.len() as u64, "folder")
		);
		if self.steps.is_live() {
			self.steps.clear();
			self.steps.conclude(error.is_none(), &line);
		} else {
			eprintln!("{line}");
		}
	}
}

impl Progress for Live {
	fn folder_start(&mut self, report: &FolderReport) {
		self.steps.begin(&title(report));
	}

	// The spinner row keeps time while a folder copies; restarting it per
	// batch would leave a finished row behind for every batch.
	fn folder_progress(&mut self, _report: &FolderReport) {}

	fn folder_done(&mut self, report: &FolderReport) {
		if self.quiet || self.dry_run {
			return;
		}
		let line = format!("{}  {}", title(report), facts(report));
		match crate::cli::term::stderr(false) {
			Some(decor) if self.steps.is_live() => {
				self.steps.clear();
				let took = std::time::Duration::from_secs_f64(report.seconds);
				let row = row(Mark::Done, &line, 0, took, decor);
				crate::cli::term::live::quiet(|| {
					let _ = writeln!(std::io::stderr(), "{row}");
				});
			}
			_ => eprintln!("{line} in {:.1}s", report.seconds),
		}
	}

	fn skipped(&mut self, skipped: &Skipped) {
		if !self.quiet {
			style::warn(format_args!(
				"skipping folder \"{}\": {}",
				crate::cli::term::sanitize(&skipped.folder),
				skipped.reason
			));
		}
	}
}

fn title(report: &FolderReport) -> String {
	format!(
		"{} into {}",
		crate::cli::term::sanitize(&report.remote),
		report.local
	)
}

/// `120 messages, 4.2 MB, 1.1 MB/s` plus what was left out.
fn facts(report: &FolderReport) -> String {
	let mut text = format!(
		"{} {}, {}",
		report.copied,
		plural(report.copied, "message"),
		bytes(report.bytes)
	);
	if report.bytes > 0 && report.seconds > 0.0 {
		let rate = (report.bytes as f64 / report.seconds) as u64;
		text.push_str(&format!(", {}/s", bytes(rate)));
	}
	for (count, what) in [
		(report.duplicates, "already here"),
		(report.deleted, "marked deleted"),
		(report.too_large, "too large"),
		(report.vanished, "gone before fetching"),
	] {
		if count > 0 {
			text.push_str(&format!(", {count} {what}"));
		}
	}
	if report.restarted {
		text.push_str(" (UIDVALIDITY changed, checked against what was copied)");
	}
	text
}

/// `word` with an `s` unless `count` is one.
fn plural(count: u64, word: &str) -> String {
	if count == 1 {
		word.to_string()
	} else {
		format!("{word}s")
	}
}

/// A byte count for people: `512 B`, `4.2 KB`, `88.1 MB`, `1.3 GB`.
pub(super) fn bytes(count: u64) -> String {
	const UNITS: [&str; 4] = ["KB", "MB", "GB", "TB"];
	if count < 1024 {
		return format!("{count} B");
	}
	let mut value = count as f64 / 1024.0;
	let mut unit = 0;
	while value >= 1024.0 && unit + 1 < UNITS.len() {
		value /= 1024.0;
		unit += 1;
	}
	format!("{value:.1} {}", UNITS[unit])
}

/// The dry-run plan on stdout: one line per folder, tab-separated, then the
/// folders left out.
pub(super) fn plan(summary: &Summary, out: &mut impl Write) {
	let _ = writeln!(out, "REMOTE\tLOCAL\tMESSAGES\tSIZE");
	for folder in &summary.folders {
		let _ = writeln!(
			out,
			"{}\t{}\t{}\t{}",
			crate::cli::term::sanitize(&folder.remote),
			folder.local,
			folder.messages,
			bytes(folder.planned_bytes)
		);
	}
	for skipped in &summary.skipped {
		let _ = writeln!(
			out,
			"{}\t-\tskipped: {}",
			crate::cli::term::sanitize(&skipped.folder),
			skipped.reason
		);
	}
}
