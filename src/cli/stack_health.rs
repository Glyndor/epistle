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

/// Poll `podup ps` until `service` is running and healthy, or until
/// `timeout`. A service without a healthcheck counts once it runs. `Err`
/// says what it last saw.
pub(super) fn wait_healthy(
	podup: &str,
	compose: &Path,
	service: &str,
	timeout: Duration,
) -> Result<(), String> {
	let deadline = Instant::now() + timeout;
	let mut last: String;
	loop {
		match super::stack_started::ps_json_with(podup, compose, Duration::from_secs(10)) {
			Ok(json) => match service_status(&json, service) {
				Some((state, health))
					if state == "running" && (health == "healthy" || health.is_empty()) =>
				{
					return Ok(());
				}
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
		std::thread::sleep(Duration::from_secs(2));
	}
}

#[cfg(test)]
#[path = "stack_health_tests.rs"]
mod tests;
