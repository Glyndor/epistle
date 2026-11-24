//! What Podman does when a service's healthcheck gives up. podup reads
//! `x-podman-on-failure` under `healthcheck`; without it an unhealthy
//! container stays unhealthy and nothing acts on it (`podup audit` reports
//! `no_health_action`). Measured on Podman 6.2.0: `restart` brings the
//! container back, `kill` leaves it exited and `stop` leaves it stopped.

use serde_json::{Value, json};

use super::render;
use super::*;

const IMAGE: &str = "ghcr.io/glyndor/epistle-panel:0.3.1";

/// Every service of the stack that has a healthcheck: mail, db, clamav and
/// the panel.
fn full_stack() -> Value {
	let mut answers = stack_answers();
	answers.services.api = true;
	answers.services.panel_image = Some(IMAGE.to_string());
	render(&answers, true)
}

#[test]
fn the_stateless_services_restart_when_their_check_gives_up() {
	let value = full_stack();
	for service in ["mail", "clamav", "panel"] {
		assert_eq!(
			value["services"][service]["healthcheck"]["x-podman-on-failure"],
			json!("restart"),
			"{service} must be restarted when it turns unhealthy"
		);
	}
}

/// The database check gives up after 150 s with no start period, which is
/// shorter than the crash recovery of a large database; a restart in the
/// middle of one only starts it over.
#[test]
fn the_database_is_not_restarted_when_its_check_gives_up() {
	let value = full_stack();
	let check = &value["services"]["db"]["healthcheck"];
	assert!(check.is_object(), "the db keeps its healthcheck: {check}");
	assert!(
		check.get("x-podman-on-failure").is_none(),
		"the db must not get a health action: {check}"
	);
}

#[test]
fn a_service_without_a_healthcheck_gets_no_action() {
	let value = full_stack();
	for name in ["certs", "freshclam"] {
		let service = &value["services"][name];
		if service.is_null() {
			continue;
		}
		assert!(
			service.get("healthcheck").is_none(),
			"{name}: an action without a check does nothing"
		);
	}
}
