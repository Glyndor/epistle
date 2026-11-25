//! When the `mail` service of the compose stack last started, for
//! `epistle status`. Read-only and bounded: it asks `podup ps` and never
//! touches the Podman socket setup that `epistle stack` repairs.

use std::path::Path;
use std::time::{Duration, Instant};

use serde::Deserialize;

use super::{build_command, compose_path};
use crate::cli::status::parse_rfc3339;

/// What `podup ps` is reported to have done when it ran out of time.
const TIMED_OUT: &str = "podup ps timed out";

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
	ps_json_until(podup, compose, Instant::now() + timeout).map_err(|error| {
		if error == TIMED_OUT {
			format!("podup ps timed out after {}s", timeout.as_secs())
		} else {
			error
		}
	})
}

/// `podup ps --format json`, killed with what it started at `until`, and its
/// output collected within that time too.
pub(in crate::cli) fn ps_json_until(
	podup: &str,
	compose: &Path,
	until: Instant,
) -> Result<String, String> {
	let mut command = build_command(podup, compose, &["ps", "--format", "json"]);
	let (status, bytes) =
		crate::cli::status::bounded::output_until(&mut command, until).map_err(|error| {
			if error.contains("over") {
				TIMED_OUT.to_string()
			} else {
				format!("podup ps: {error}")
			}
		})?;
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
mod tests;
