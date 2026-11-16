//! The services of the stack that should run and do not.
//!
//! The boot unit starts the stack once and a container that fails to start
//! leaves no trace in the unit's own state, so this reads what runs now and
//! names each service that does not, with the last line the unit's journal
//! has about it and the command that starts it.

use std::path::Path;

use serde_json::Value;

use super::compose_items::{enabled, services};
use super::host::BootHost;
use super::unit_items;
use crate::cli::status::report::{Item, Level};

/// One row of `podup ps --format json`.
#[derive(Debug, PartialEq, Eq)]
struct Row {
	service: String,
	state: String,
	exit_code: i64,
}

fn parse(text: &str) -> Result<Vec<Row>, String> {
	let rows: Vec<Value> = serde_json::from_str(text).map_err(|error| {
		format!("`podup ps --format json` printed no list of services: {error}")
	})?;
	Ok(rows
		.iter()
		.filter_map(|row| {
			Some(Row {
				service: row["Service"].as_str()?.to_string(),
				state: row["State"].as_str().unwrap_or_default().to_string(),
				exit_code: row["ExitCode"].as_i64().unwrap_or(0),
			})
		})
		.collect())
}

/// The last line of the unit's journal that names `service`.
fn last_error(log: &str, service: &str) -> Option<String> {
	log.lines()
		.rev()
		.map(str::trim)
		.find(|line| !line.is_empty() && line.contains(service))
		.map(str::to_string)
}

/// Every enabled service has a running container, judged once the boot unit
/// has finished. A service that is down is named with its state, the last
/// line of the unit's journal about it and the command that starts it.
pub(super) fn running(host: &mut impl BootHost, text: &str, compose: &Path) -> Item {
	let wanted = match services(text) {
		Ok(services) => services,
		Err(error) => return Item::new("services", Level::Warn, error),
	};
	let (active, result) = unit_items::state(host);
	if active == "activating" {
		return Item::new(
			"services",
			Level::Warn,
			"the boot unit is still starting the stack, so the services are not judged yet; read it with `systemctl --user status podup-epistle.service`",
		);
	}
	let rows = match host.ps_json(compose).and_then(|text| parse(&text)) {
		Ok(rows) => rows,
		Err(error) => return Item::new("services", Level::Warn, error),
	};
	let log = host.unit_log().unwrap_or_default();
	let mut down = Vec::new();
	for (name, service) in wanted.iter().filter(|(_, service)| enabled(service)) {
		let row = rows.iter().find(|row| &row.service == name);
		if row.is_some_and(|row| row.state == "running") {
			continue;
		}
		let kept_stopped = matches!(service["restart"].as_str(), None | Some("no"));
		if row.is_some_and(|row| row.state == "exited" && row.exit_code == 0) && kept_stopped {
			// A job that finished and is not meant to start again.
			continue;
		}
		let (seen, start) = match row {
			Some(row) if row.exit_code != 0 => (
				format!("{name} is {} with status {}", row.state, row.exit_code),
				format!("sudo epistle stack start {name}"),
			),
			Some(row) => (
				format!("{name} is {}", row.state),
				format!("sudo epistle stack start {name}"),
			),
			None => (
				format!("{name} has no container"),
				"sudo epistle stack up".to_string(),
			),
		};
		let why = last_error(&log, name)
			.map(|line| format!("; the last line about it in the unit's journal is `{line}`"))
			.unwrap_or_default();
		down.push((format!("{seen}{why}"), start));
	}
	if down.is_empty() {
		return Item::new(
			"services",
			Level::Ok,
			"every service of the stack is running",
		);
	}
	let finished_badly = result != "success" || active == "failed";
	let level = if finished_badly {
		Level::Fail
	} else {
		Level::Warn
	};
	let story = down
		.iter()
		.map(|(what, start)| format!("{what}; start it with `{start}`"))
		.collect::<Vec<_>>()
		.join("; ");
	Item::new("services", level, story)
}
