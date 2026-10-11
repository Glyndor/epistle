//! Result types and rendering shared by every `epistle status` check.

use std::io::Write;

use serde::Serialize;

use super::CheckArea;

/// Outcome of one check. The ordering is the severity ordering, so the worst
/// outcome of a set is its `max`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum Level {
	/// Working as expected, or not configured.
	Ok,
	/// Working, but an operator should look soon.
	Warn,
	/// Broken, or about to be.
	Fail,
}

impl Level {
	pub(super) fn as_str(self) -> &'static str {
		match self {
			Level::Ok => "ok",
			Level::Warn => "warn",
			Level::Fail => "fail",
		}
	}
}

/// One finding inside an area, such as a single listener or domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct Item {
	/// What was checked, for example `smtp 127.0.0.1:25`.
	pub(super) name: String,
	/// Outcome for this item.
	pub(super) status: Level,
	/// One-line explanation.
	pub(super) detail: String,
}

impl Item {
	pub(super) fn new(name: impl Into<String>, status: Level, detail: impl Into<String>) -> Self {
		Item {
			name: name.into(),
			status,
			detail: detail.into(),
		}
	}
}

/// The result of one area: a verdict, a short summary and the findings behind it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct AreaReport {
	/// Worst status among the items, or the single verdict when there are none.
	pub(super) status: Level,
	/// Short summary shown on the `status` line.
	pub(super) detail: String,
	/// The individual findings.
	pub(super) items: Vec<Item>,
}

impl AreaReport {
	/// A verdict without findings behind it.
	pub(super) fn single(status: Level, detail: impl Into<String>) -> Self {
		AreaReport {
			status,
			detail: detail.into(),
			items: Vec::new(),
		}
	}

	/// The area is healthy, or has nothing to check.
	pub(super) fn ok(detail: impl Into<String>) -> Self {
		Self::single(Level::Ok, detail)
	}

	/// The area is broken.
	pub(super) fn fail(detail: impl Into<String>) -> Self {
		Self::single(Level::Fail, detail)
	}

	/// Roll a set of findings up: the area status is the worst item status.
	pub(super) fn from_items(items: Vec<Item>, summary: impl Into<String>) -> Self {
		let status = items
			.iter()
			.map(|item| item.status)
			.max()
			.unwrap_or(Level::Ok);
		AreaReport {
			status,
			detail: summary.into(),
			items,
		}
	}
}

/// Whether any area failed; this decides the exit code.
pub(super) fn any_failed(reports: &[(CheckArea, AreaReport)]) -> bool {
	reports
		.iter()
		.any(|(_, report)| report.status == Level::Fail)
}

/// Print an aligned table: one line per area, and with `show_items` the
/// findings under each line.
pub(super) fn render_table(
	reports: &[(CheckArea, AreaReport)],
	show_items: bool,
	out: &mut impl Write,
) -> std::io::Result<()> {
	for (area, report) in reports {
		writeln!(
			out,
			"{:<10} {:<5} {}",
			area.name(),
			report.status.as_str(),
			report.detail
		)?;
		if show_items {
			for item in &report.items {
				writeln!(
					out,
					"  {:<5} {}: {}",
					item.status.as_str(),
					item.name,
					item.detail
				)?;
			}
		}
	}
	Ok(())
}

/// Print one JSON object keyed by area name.
pub(super) fn render_json(
	reports: &[(CheckArea, AreaReport)],
	out: &mut impl Write,
) -> std::io::Result<()> {
	let map: std::collections::BTreeMap<&str, &AreaReport> = reports
		.iter()
		.map(|(area, report)| (area.name(), report))
		.collect();
	serde_json::to_writer_pretty(&mut *out, &map).map_err(std::io::Error::other)?;
	writeln!(out)
}
