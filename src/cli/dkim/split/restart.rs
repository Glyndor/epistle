//! The restart a split depends on: repeating one that never happened,
//! confirming one done by hand, and the exit code when the server is not
//! confirmed to run the moved keys.

use std::io::Write;
use std::process::ExitCode;

use super::{Options, finish};
use crate::cli::json_out::Report;
use crate::cli::resource::ResourceError;
use crate::config::Config;
use crate::dkim::split_state;

/// Whether `config` has a `[[dkim.domain]]` entry for `domain`: a record of a
/// move with no entry behind it is not a restart to wait for or to confirm.
pub(super) fn has_entry(config: &Config) -> impl Fn(&str) -> bool + '_ {
	move |domain| {
		config
			.dkim
			.as_ref()
			.is_some_and(|dkim| dkim.override_for(domain).is_some())
	}
}

/// `split` found nothing to move. If an earlier run wrote its entries and the
/// server was never restarted onto them, the restart is repeated: the keys on
/// disk are not the ones that sign until it happens.
pub(super) fn nothing_to_split(
	config: &Config,
	options: &Options,
	(json, out, err): (bool, &mut impl Write, &mut impl Write),
	restart: impl FnOnce(&Config, crate::cli::stack::StackAction) -> ExitCode,
) -> ExitCode {
	let mut report = Report::new(out, json);
	let pending = match split_state::pending(&config.data_dir, has_entry(config)) {
		Ok(pending) => pending,
		Err(why) => {
			crate::cli::style::error_to(err, format_args!("dkim split refused: {why}"));
			return ExitCode::FAILURE;
		}
	};
	if pending.is_empty() {
		report.line("nothing to split: every hosted domain has a key of its own");
		return report.object(serde_json::json!({ "result": "unchanged", "action": "split" }));
	}
	if options.dry_run {
		// A dry run only looks: it neither restarts the server nor records
		// that it was restarted.
		report.line(format_args!(
			"{} signs with the shared key until the server is restarted onto its own; a real run restarts it (dry run: nothing done)",
			pending.join(", ")
		));
		return report.object(serde_json::json!({
			"result": "dry-run", "action": "split", "restart_pending": pending,
		}));
	}
	report.line(format_args!(
		"{} signs with the shared key until the server is restarted onto its own: restarting now",
		pending.join(", ")
	));
	let (confirmed, reload) = match restart_onto(
		config,
		crate::cli::config_edit::Outcome::Changed,
		err,
		restart,
	) {
		Ok(done) => done,
		Err(code) => return code,
	};
	let pending_code = (!confirmed).then(|| restart_pending(&mut report));
	if confirmed {
		report.line("the server was restarted onto the moved keys");
	}
	let code = report.object(serde_json::json!({
		"result": if confirmed { "restarted" } else { "restart-pending" },
		"action": "split",
		"domains": pending,
		"reload": reload.name(),
	}));
	match pending_code {
		Some(pending) if code == ExitCode::SUCCESS => pending,
		_ => code,
	}
}

/// Restart the server and, when that is confirmed, record that the moved keys
/// are the ones signing. `Ok((confirmed, reload))`; `Err` carries the exit code
/// of an error that kept the restart from being attempted.
pub(super) fn restart_onto(
	config: &Config,
	outcome: crate::cli::config_edit::Outcome,
	err: &mut impl Write,
	restart: impl FnOnce(&Config, crate::cli::stack::StackAction) -> ExitCode,
) -> Result<(bool, crate::cli::json_out::Reload), ExitCode> {
	// A restart that fails is not an error of this command: the move is
	// written and not confirmed, which is the pending state (exit 4), so the
	// code the restart returned is never the one this command exits with.
	let reload = match crate::cli::config_edit::after_change_reporting(
		config, outcome, true, err, restart,
	) {
		Ok((_, reload)) => reload,
		Err(ResourceError::Refusal(message) | ResourceError::Failure(message)) => {
			crate::cli::style::error_to(err, message);
			return Err(ExitCode::FAILURE);
		}
	};
	let confirmed = reload == crate::cli::json_out::Reload::Restarted;
	if confirmed
		&& let Err(why) = split_state::mark_restarted(
			&config.data_dir,
			crate::cli::dkim::now_epoch(),
			has_entry(config),
		) {
		crate::cli::style::error_to(err, format_args!("{why}"));
		return Err(ExitCode::FAILURE);
	}
	Ok((confirmed, reload))
}

/// What to say, and the exit code, when the server is not confirmed to run the
/// moved keys: 4, the code of a split that still needs the operator.
pub(super) fn restart_pending(report: &mut Report<'_>) -> ExitCode {
	report.line(
		"the server is NOT confirmed to run the moved keys: restart it, then run `epistle dkim split --restarted` (or `epistle dkim split` again, which restarts it if it can)",
	);
	ExitCode::from(finish::MANUAL_ACTION)
}

/// `--restarted`: the operator restarted the server by hand.
pub(super) fn confirm_restart(
	config: &Config,
	(json, out, err): (bool, &mut impl Write, &mut impl Write),
) -> ExitCode {
	let mut report = Report::new(out, json);
	match split_state::mark_restarted(
		&config.data_dir,
		crate::cli::dkim::now_epoch(),
		has_entry(config),
	) {
		Ok(settled) if settled.is_empty() => {
			report.line("nothing pending: no split is waiting for a restart");
			report.object(serde_json::json!({ "result": "unchanged", "action": "split-restarted" }))
		}
		Ok(settled) => {
			report.line(format_args!(
				"recorded that the server runs the moved keys of {}; the overlap before the shared key's records may go counts from now",
				settled.join(", ")
			));
			report.object(serde_json::json!({
				"result": "restarted", "action": "split-restarted", "domains": settled,
			}))
		}
		Err(why) => {
			crate::cli::style::error_to(err, format_args!("{why}"));
			ExitCode::FAILURE
		}
	}
}
