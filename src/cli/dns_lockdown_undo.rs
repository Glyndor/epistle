//! `epistle dns lockdown --undo`: show what the journal's records would
//! become, ask, then remove the ones still as published and put back the
//! DMARC record the lockdown replaced. The journal keeps whatever could
//! not be undone because the provider failed, so the next try resumes.

use std::io::Write;
use std::process::ExitCode;
use std::sync::Arc;

use super::{Target, render, store_journal};
use crate::cli::style;
use crate::dns::lockdown::{self, Journal};
use crate::dns::provider::DnsProvider;

/// Run the undo for `target`.
#[allow(clippy::too_many_arguments)]
pub(super) fn run(
	runtime: &tokio::runtime::Runtime,
	provider: Option<Arc<dyn DnsProvider>>,
	target: &Target<'_>,
	journal: Option<Journal>,
	yes: bool,
	dry_run: bool,
	out: &mut impl Write,
	err: &mut impl Write,
) -> ExitCode {
	let Some(journal) = journal else {
		let _ = writeln!(
			err,
			"no lockdown journal for {}; nothing to undo",
			target.domain
		);
		return ExitCode::SUCCESS;
	};
	let Some(provider) = provider else {
		let _ = writeln!(
			out,
			"no DNS provider is configured; undo these records by hand:"
		);
		for entry in &journal.entries {
			match &entry.replaced {
				Some(original) => {
					let _ = writeln!(out, "  put back: {}", render::record_line(original));
				}
				None => {
					let _ = writeln!(out, "  remove: {}", render::record_line(&entry.record));
				}
			}
		}
		return ExitCode::SUCCESS;
	};
	let preview = match runtime.block_on(lockdown::undo_journal(
		provider.as_ref(),
		target.zone,
		&journal,
		true,
	)) {
		Ok(report) => report,
		Err(failure) => {
			style::error_to(err, failure.message);
			return ExitCode::FAILURE;
		}
	};
	let _ = out.write_all(render::undo_text(target.domain, &preview, true).as_bytes());
	let writes = preview.deleted.len() + preview.restored.len();
	if dry_run {
		let _ = writeln!(err, "dry run: nothing was changed");
		return ExitCode::SUCCESS;
	}
	if writes > 0 {
		let question = format!("Undo these {writes} records in the {} zone?", target.zone);
		if let Err(code) =
			crate::cli::prompt::confirm_destructive("dns lockdown --undo", &question, yes)
		{
			return code;
		}
	}
	let undone = if writes == 0 {
		Ok(preview)
	} else {
		runtime.block_on(lockdown::undo_journal(
			provider.as_ref(),
			target.zone,
			&journal,
			false,
		))
	};
	match undone {
		Ok(report) => {
			if let Err(error) = std::fs::remove_file(target.journal_path)
				&& error.kind() != std::io::ErrorKind::NotFound
			{
				style::error_to(
					err,
					format_args!(
						"cannot remove the journal {}: {error}",
						target.journal_path.display()
					),
				);
				return ExitCode::FAILURE;
			}
			let _ = writeln!(
				err,
				"undone: {} deleted, {} restored, {} left as is; journal removed",
				report.deleted.len(),
				report.restored.len(),
				report.changed.len() + report.absent.len()
			);
			ExitCode::SUCCESS
		}
		Err(failure) => {
			let _ =
				out.write_all(render::undo_text(target.domain, &failure.report, false).as_bytes());
			style::error_to(err, &failure.message);
			match store_journal(target.journal_path, &failure.remaining) {
				Ok(()) => {
					let _ = writeln!(
						err,
						"the journal keeps the {} records not undone yet; run `epistle dns lockdown --undo` again",
						failure.remaining.entries.len()
					);
				}
				Err(message) => style::error_to(err, message),
			}
			ExitCode::FAILURE
		}
	}
}
