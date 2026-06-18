//! `mail queue`: inspect the outbound delivery spool from the command line.

use std::path::Path;
use std::process::ExitCode;

use crate::storage::FsSpool;

/// List the outbound spool: one line per message with its envelope and retry
/// state. Writes to `out` so the formatting is unit-testable.
pub(super) fn list(data_dir: &Path, out: &mut impl std::io::Write) -> ExitCode {
	let spool = match FsSpool::open(data_dir) {
		Ok(spool) => spool,
		Err(error) => {
			eprintln!("error: opening spool: {error}");
			return ExitCode::FAILURE;
		}
	};
	let ids = match spool.list() {
		Ok(ids) => ids,
		Err(error) => {
			eprintln!("error: reading spool: {error}");
			return ExitCode::FAILURE;
		}
	};
	for id in &ids {
		let Ok(entry) = spool.load(*id) else { continue };
		let from = if entry.envelope.reverse_path.is_empty() {
			"<>"
		} else {
			&entry.envelope.reverse_path
		};
		let _ = writeln!(
			out,
			"{id}\tattempts={}\tfrom={from}\tto={}",
			entry.envelope.attempts,
			entry.envelope.recipients.join(",")
		);
	}
	let _ = writeln!(out, "{} queued", ids.len());
	ExitCode::SUCCESS
}
