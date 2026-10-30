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
/// error messages ("database", "antivirus").
pub(super) async fn run(
	config: &crate::config::Config,
	command: std::process::Command,
	area: &'static str,
	what: &'static str,
) -> AreaReport {
	if let Err(error) = crate::cli::container::db::ensure_mail_running(config) {
		return AreaReport::fail(error);
	}
	let run = tokio::task::spawn_blocking(move || run_bounded(command, IN_CONTAINER_TIMEOUT, what));
	let stdout = match run.await {
		Ok(Ok(stdout)) => stdout,
		Ok(Err(error)) => return AreaReport::fail(error),
		Err(error) => return AreaReport::fail(format!("the {what} check task failed: {error}")),
	};
	parse(&stdout, area, what)
}

/// Run `command` to completion, killing it after `limit`; return its stdout.
fn run_bounded(
	mut command: std::process::Command,
	limit: Duration,
	what: &str,
) -> Result<Vec<u8>, String> {
	use std::io::Read;
	let mut child = command
		.stdin(std::process::Stdio::null())
		.stdout(std::process::Stdio::piped())
		.stderr(std::process::Stdio::null())
		.spawn()
		.map_err(|error| format!("cannot run podup: {error}"))?;
	let deadline = std::time::Instant::now() + limit;
	loop {
		match child.try_wait() {
			Ok(Some(_)) => break,
			Ok(None) if std::time::Instant::now() < deadline => {
				std::thread::sleep(Duration::from_millis(100));
			}
			Ok(None) => {
				let _ = child.kill();
				let _ = child.wait();
				return Err(format!("the {what} check in the mail container timed out"));
			}
			Err(error) => return Err(format!("cannot wait for podup: {error}")),
		}
	}
	let mut stdout = Vec::new();
	if let Some(mut pipe) = child.stdout.take() {
		pipe.read_to_end(&mut stdout)
			.map_err(|error| format!("cannot read podup output: {error}"))?;
	}
	Ok(stdout)
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
