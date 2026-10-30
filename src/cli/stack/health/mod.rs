//! Waiting for a stack service to report healthy, from `podup ps`.

use std::path::Path;
use std::time::{Duration, Instant};

use serde::Deserialize;

#[derive(Deserialize)]
struct Row {
	#[serde(rename = "Service")]
	service: String,
	#[serde(rename = "State", default)]
	state: String,
	#[serde(rename = "Health", default)]
	health: String,
}

/// The `(state, health)` podup reports for `service`, if it lists it.
pub(super) fn service_status(json: &str, service: &str) -> Option<(String, String)> {
	let rows: Vec<Row> = serde_json::from_str(json).ok()?;
	rows.into_iter()
		.find(|row| row.service == service)
		.map(|row| (row.state, row.health))
}

/// Poll `podup ps` until `service` is ready, or until `timeout`. A service
/// whose compose definition has a healthcheck is ready only when podup
/// reports it `healthy`: podup reports an empty health while the check is
/// still in its start period (measured on podup 5.10.18, where `Status`
/// said `starting` and `Health` was `""`), and treating that as healthy
/// let `stack update` judge mail before it listened. A service without a
/// healthcheck is ready once it runs. `Err` says what it last saw.
pub(in crate::cli) fn wait_healthy(
	podup: &str,
	compose: &Path,
	service: &str,
	timeout: Duration,
) -> Result<(), String> {
	wait_with_interval(podup, compose, service, timeout, Duration::from_secs(2))
}

/// [`wait_healthy`] polling every `interval`.
pub(super) fn wait_with_interval(
	podup: &str,
	compose: &Path,
	service: &str,
	timeout: Duration,
	interval: Duration,
) -> Result<(), String> {
	let checked = crate::cli::regular::read::read_to_string(compose)
		.map_err(|error| format!("cannot read {}: {error}", compose.display()))
		.map(|text| has_healthcheck(&text, service))?;
	let deadline = Instant::now() + timeout;
	let mut last: String;
	loop {
		match super::started::ps_json_with(podup, compose, Duration::from_secs(10)) {
			Ok(json) => match service_status(&json, service) {
				Some((state, health)) if ready(&state, &health, checked) => return Ok(()),
				Some((state, health)) => last = format!("{state}, health {health:?}"),
				None => last = "not listed by podup ps".to_string(),
			},
			Err(error) => last = error,
		}
		if Instant::now() >= deadline {
			return Err(format!(
				"{service} was not healthy after {}s (last seen: {last})",
				timeout.as_secs()
			));
		}
		std::thread::sleep(interval);
	}
}

/// Whether a service in this state counts as ready.
fn ready(state: &str, health: &str, checked: bool) -> bool {
	state == "running" && (!checked || health == "healthy")
}

/// Whether the compose file gives `service` a healthcheck that is not
/// switched off (`disable: true`, or a test of `["NONE"]`).
pub(super) fn has_healthcheck(compose: &str, service: &str) -> bool {
	let Ok(document) = serde_json::from_str::<serde_json::Value>(compose) else {
		return true;
	};
	let check = &document["services"][service]["healthcheck"];
	check.is_object()
		&& check["disable"] != serde_json::Value::Bool(true)
		&& check["test"] != serde_json::json!(["NONE"])
}

#[cfg(test)]
mod tests;
