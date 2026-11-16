//! The items read from the compose file: restart policies and images.

use serde_json::Value;

use super::host::BootHost;
use crate::cli::status::report::{Item, Level};

pub(super) fn services(text: &str) -> Result<Vec<(String, Value)>, String> {
	let document: Value = serde_json::from_str(text).map_err(|error| {
		format!("the compose file is not the JSON epistle init writes: {error}")
	})?;
	Ok(document["services"]
		.as_object()
		.map(|map| {
			map.iter()
				.map(|(name, value)| (name.clone(), value.clone()))
				.collect()
		})
		.unwrap_or_default())
}

/// A service with `profiles` is not started by a plain `up -d`.
pub(super) fn enabled(service: &Value) -> bool {
	service["profiles"]
		.as_array()
		.is_none_or(|list| list.is_empty())
}

/// No service has the restart policy `no`, which a compose file also has when
/// it says nothing: such a container stays down once it exits.
pub(super) fn restart(text: &str) -> Item {
	let services = match services(text) {
		Ok(services) => services,
		Err(error) => return Item::new("restart policy", Level::Warn, error),
	};
	let without: Vec<&str> = services
		.iter()
		.filter(|(_, service)| enabled(service))
		.filter(|(_, service)| matches!(service["restart"].as_str(), None | Some("no")))
		.map(|(name, _)| name.as_str())
		.collect();
	if without.is_empty() {
		return Item::new(
			"restart policy",
			Level::Ok,
			"every service restarts unless stopped",
		);
	}
	Item::new(
		"restart policy",
		Level::Warn,
		format!(
			"{} has the restart policy `no`, so it stays down after it exits; `sudo epistle stack update` renders the file again, and a service you added yourself needs `restart: unless-stopped` in its definition",
			without.join(", ")
		),
	)
}

/// Every image the compose file names is in the account's storage. The unit
/// starts with `--pull never`, so a missing image fails the start after a
/// reboot; only `stack update` pulls, and this check never does.
pub(super) fn images(host: &mut impl BootHost, text: &str) -> Item {
	let services = match services(text) {
		Ok(services) => services,
		Err(error) => return Item::new("images", Level::Warn, error),
	};
	let (mut missing, mut missing_disabled) = (Vec::new(), Vec::new());
	for (name, service) in &services {
		let Some(image) = service["image"].as_str() else {
			continue;
		};
		match host.image_exists(image) {
			Ok(true) => {}
			Ok(false) if enabled(service) => missing.push(format!("{name} ({image})")),
			Ok(false) => missing_disabled.push(format!("{name} ({image})")),
			Err(error) => return Item::new("images", Level::Warn, error),
		}
	}
	if !missing.is_empty() {
		return Item::new(
			"images",
			Level::Fail,
			format!(
				"{} is not in the container storage, and the unit starts with `--pull never`, so the start fails after a reboot; run `sudo epistle stack update`, which pulls the versions",
				missing.join(", ")
			),
		);
	}
	if !missing_disabled.is_empty() {
		return Item::new(
			"images",
			Level::Warn,
			format!(
				"{} is not in the container storage; that service is not enabled, so the boot does not need it",
				missing_disabled.join(", ")
			),
		);
	}
	Item::new(
		"images",
		Level::Ok,
		"every image is in the container storage",
	)
}
