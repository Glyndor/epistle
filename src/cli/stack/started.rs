//! When the `mail` service of the compose stack last started, for
//! `epistle status`. Read-only and bounded: it asks `podup ps` and never
//! touches the Podman socket setup that `epistle stack` repairs.

use std::io::Read;
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

use serde::Deserialize;

use super::{build_command, compose_path};
use crate::cli::status::parse_rfc3339;

/// How long `podup ps` may take before it is abandoned.
pub(in crate::cli) const PS_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Deserialize)]
struct Row {
	#[serde(rename = "Service")]
	service: String,
	#[serde(rename = "StartedAt", default)]
	started_at: Option<serde_json::Value>,
}

/// Epoch seconds at which the `mail` container started.
///
/// `Ok(None)` when the installation has no compose stack (the start time is
/// then not observable); `Err` carries the reason it could not be read.
pub(in crate::cli) fn mail_started_at(data_dir: &Path, podup: &str) -> Result<Option<i64>, String> {
	let compose = compose_path(data_dir);
	if !compose.exists() {
		return Ok(None);
	}
	started_at_with(podup, &compose, PS_TIMEOUT).map(Some)
}

fn started_at_with(podup: &str, compose: &Path, timeout: Duration) -> Result<i64, String> {
	parse_started(&ps_json_with(podup, compose, timeout)?)
}

pub(in crate::cli) fn ps_json_with(
	podup: &str,
	compose: &Path,
	timeout: Duration,
) -> Result<String, String> {
	let mut child = build_command(podup, compose, &["ps", "--format", "json"])
		.stdin(Stdio::null())
		.stdout(Stdio::piped())
		.stderr(Stdio::null())
		.spawn()
		.map_err(|error| format!("cannot run {podup}: {error}"))?;
	let mut stdout = child.stdout.take().ok_or("no stdout from podup")?;
	let reader = std::thread::spawn(move || {
		let mut bytes = Vec::new();
		let _ = stdout.read_to_end(&mut bytes);
		bytes
	});
	let deadline = Instant::now() + timeout;
	let status = loop {
		match child.try_wait() {
			Ok(Some(status)) => break status,
			Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
			Ok(None) => {
				let _ = child.kill();
				let _ = child.wait();
				return Err(format!("podup ps timed out after {}s", timeout.as_secs()));
			}
			Err(error) => return Err(format!("waiting for podup: {error}")),
		}
	};
	let bytes = reader.join().map_err(|_| "reading podup output failed")?;
	if !status.success() {
		return Err(format!("podup ps exited with {status}"));
	}
	Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// The `mail` row's `StartedAt`, as an RFC 3339 string or epoch seconds.
fn parse_started(json: &str) -> Result<i64, String> {
	let rows: Vec<Row> =
		serde_json::from_str(json).map_err(|error| format!("podup ps output: {error}"))?;
	let row = rows
		.into_iter()
		.find(|row| row.service == "mail")
		.ok_or("the mail service is not running")?;
	match row.started_at {
		Some(serde_json::Value::Number(number)) => number
			.as_i64()
			.ok_or_else(|| "StartedAt is not a whole number".to_string()),
		Some(serde_json::Value::String(text)) => {
			parse_rfc3339(&text).ok_or_else(|| "StartedAt is not a timestamp".to_string())
		}
		_ => Err("podup does not report when the container started".to_string()),
	}
}

#[cfg(test)]
#[path = "started_tests.rs"]
mod tests;
