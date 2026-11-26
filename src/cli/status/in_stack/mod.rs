//! Run one check in the mail container when the socket it needs is only
//! mounted there. The database and clamd sockets live on named volumes of
//! the compose stack, so a check run from the host asks the mail container,
//! the only place the server itself connects from.

use std::time::Duration;

use super::report::AreaReport;

/// How long the check inside the container may take: the check itself is
/// bounded by its own 5 seconds, plus starting the exec.
const IN_CONTAINER_TIMEOUT: Duration = Duration::from_secs(20);

/// Run `command` (an `epistle check <area> --json` in the mail container)
/// and return the `area` entry of its report. `what` names the check in
/// error messages ("database", "antivirus"). Looking at the stack and running
/// the command both happen on a blocking thread that keeps the run's place until
/// they return, and both programs are killed, with what they started, at the
/// time of the run.
pub(super) async fn run(
	ctx: &super::Ctx,
	config: &crate::config::Config,
	command: std::process::Command,
	area: &'static str,
	what: &'static str,
) -> AreaReport {
	let config = config.clone();
	let podup = ctx.podup.clone();
	let until = ctx
		.deadline
		.min(std::time::Instant::now() + IN_CONTAINER_TIMEOUT);
	let run = ctx.blocking(move || {
		crate::cli::container::db::ensure_mail_running_until(&config, &podup, until)?;
		run_bounded(command, until, what)
	});
	let stdout = match run.await {
		Ok(Ok(stdout)) => stdout,
		Ok(Err(error)) => return AreaReport::fail(error),
		Err(error) => return AreaReport::fail(format!("the {what} check task failed: {error}")),
	};
	parse(&stdout, area, what)
}

/// Run `command` to completion, killing it, and what it started, at `until`;
/// return its stdout.
fn run_bounded(
	mut command: std::process::Command,
	until: std::time::Instant,
	what: &str,
) -> Result<Vec<u8>, String> {
	super::bounded::output_until(&mut command, until)
		.map(|(_, stdout)| stdout)
		.map_err(|error| format!("the {what} check in the mail container: {error}"))
}

/// The `area` entry of `epistle check <area> --json` as printed in the
/// container.
fn parse(stdout: &[u8], area: &str, what: &str) -> AreaReport {
	serde_json::from_slice::<std::collections::BTreeMap<String, AreaReport>>(stdout)
		.ok()
		.and_then(|mut areas| areas.remove(area))
		.unwrap_or_else(|| {
			AreaReport::fail(format!(
				"the {what} check in the mail container gave no answer"
			))
		})
}

#[cfg(test)]
mod tests;
