//! The summary `init`, `stack up` and `stack update` print at their end.

use crate::cli::status::boot_area;
use crate::cli::status::report::{AreaReport, Level};
use crate::config::Config;
use std::io::Write;

/// Print what would stop the stack from coming back after a reboot, one line
/// per item that is not `ok` with the command that fixes it, or one line that
/// says it does. A host without a compose file prints nothing: it has no
/// stack to bring back.
pub(in crate::cli) fn print_summary(config: &Config, out: &mut (impl Write + ?Sized)) {
	let report = boot_area::judge(&mut boot_area::host::Live::new(), config, true);
	render(&report, out);
}

/// Write `report` the way [`print_summary`] does.
pub(super) fn render(report: &AreaReport, out: &mut (impl Write + ?Sized)) {
	if report.items.is_empty() {
		return;
	}
	let _ = writeln!(out, "epistle: boot: {}", report.detail);
	for item in report.items.iter().filter(|item| item.status != Level::Ok) {
		let _ = writeln!(
			out,
			"epistle:   {} {}: {}",
			item.status.as_str(),
			item.name,
			item.detail
		);
	}
}
