//! Switching the domains onto their own keys once the records are published.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use crate::cli::config_edit::ConfigDocument;
use crate::cli::domain::own_key::add_entry;
use crate::cli::json_out::Report;
use crate::config::Config;
use crate::dkim::split_state;
use crate::dkim::stale::Stale;

use super::moves::{Move, describe, report_stale};
use super::{plan, restart_onto, restart_pending};

/// Write the entries and restart: the one step that changes what signs.
pub(super) fn switch(
	path: &Path,
	config: &Config,
	(plan, moves, stale): (&plan::Plan, &[Move], &[Stale]),
	report: &mut Report<'_>,
	err: &mut impl Write,
	restart: impl FnOnce(&Config, crate::cli::stack::StackAction) -> ExitCode,
) -> ExitCode {
	// What a later run needs is written first: the moved domains and the shared
	// key's selectors they leave behind. A run that dies after this and before
	// the entries are saved leaves a record of a move that did not happen,
	// which a retry settles; the other order could leave entries nobody
	// remembers.
	for m in moves {
		let selectors = stale
			.iter()
			.filter(|record| record.domain == m.domain)
			.map(|record| split_state::StaleSelector {
				selector: record.selector.clone(),
				expected: record.expected.clone(),
			})
			.collect();
		if let Err(why) = split_state::record_written(
			&config.data_dir,
			&m.domain,
			super::super::now_epoch(),
			selectors,
		) {
			crate::cli::style::error_to(err, format_args!("dkim split refused: {why}"));
			return ExitCode::FAILURE;
		}
	}
	let mut document = match ConfigDocument::open(path) {
		Ok(document) => document,
		Err(error) => {
			crate::cli::style::error_to(err, error);
			return ExitCode::FAILURE;
		}
	};
	for m in moves {
		if let Err(error) = add_entry(&mut document, &m.domain, &m.keys) {
			crate::cli::style::error_to(err, error);
			return ExitCode::FAILURE;
		}
	}
	let edited = match document.config() {
		Ok(edited) => edited,
		Err(error) => {
			crate::cli::style::error_to(err, error);
			return ExitCode::FAILURE;
		}
	};
	let outcome = match document.commit() {
		Ok(outcome) => outcome,
		Err(error) => {
			crate::cli::style::error_to(err, error);
			return ExitCode::FAILURE;
		}
	};
	for m in moves {
		report.line(format_args!(
			"{} signs with {} from the next start",
			m.domain, m.keys.selector
		));
	}
	// Only a restart that is confirmed makes the new keys the ones signing;
	// until then the domains are pending and `--finish` retires nothing.
	let (confirmed, reload) = match restart_onto(&edited, outcome, err, restart) {
		Ok(done) => done,
		Err(code) => return code,
	};
	report.line(format_args!(
		"{} keeps the [dkim] key; the shared key is still published at the domains that left it",
		plan.keeps
	));
	let pending_code = (!confirmed).then(|| restart_pending(report));
	let shown: Vec<_> = moves
		.iter()
		.map(|m| (m.domain.clone(), m.keys.clone()))
		.collect();
	let mut result = describe(plan, &shown);
	report_stale(report, &mut result, stale);
	result["result"] = if confirmed {
		"split"
	} else {
		"restart-pending"
	}
	.into();
	result["action"] = "split".into();
	result["reload"] = reload.name().into();
	let code = report.object(result);
	match pending_code {
		Some(pending) if code == ExitCode::SUCCESS => pending,
		_ => code,
	}
}
