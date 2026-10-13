//! The capabilities every generated service keeps. Each set below was
//! measured by starting the service under `cap_drop: [ALL]` and adding back
//! one capability per failure; the comments in `compose_services.rs` name the
//! failure each one answers.

use super::render;
use super::*;
use serde_json::json;

#[test]
fn every_service_drops_every_capability() {
	let value = render(&stack_answers(), true);
	let services = value["services"].as_object().expect("services");
	assert_eq!(services.len(), 4, "mail, db, clamav and freshclam");
	for (name, service) in services {
		assert_eq!(
			service["cap_drop"],
			json!(["ALL"]),
			"{name} must start from an empty capability set"
		);
	}
}

#[test]
fn only_clamd_adds_capabilities_back() {
	let value = render(&stack_answers(), true);
	assert_eq!(
		value["services"]["clamav"]["cap_add"],
		json!(["CHOWN", "FOWNER", "SETGID", "SETUID"]),
		"clamd's entrypoint chowns and chmods the socket directory as root, then clamd \
		 drops to the clamav user"
	);
	for name in ["mail", "db", "freshclam"] {
		assert!(
			value["services"][name].get("cap_add").is_none(),
			"{name} runs as an unprivileged user and needs no capability"
		);
	}
}

#[test]
fn db_runs_as_the_postgres_user_of_its_image() {
	let value = render(&stack_answers(), true);
	assert_eq!(
		value["services"]["db"]["user"], "999:999",
		"as root the entrypoint needs CHOWN, DAC_OVERRIDE, FOWNER, SETGID and SETUID to \
		 chown the volumes and step down to postgres"
	);
}

#[test]
fn freshclam_runs_the_daemon_as_clamav_instead_of_the_image_init() {
	let value = render(&stack_answers(), true);
	let fresh = &value["services"]["freshclam"];
	assert_eq!(
		fresh["user"], "100:101",
		"uid and gid of clamav in the image"
	);
	assert_eq!(
		fresh["entrypoint"],
		json!([
			"/sbin/tini",
			"--",
			"freshclam",
			"--daemon",
			"--foreground",
			"--stdout",
			"--checks=1"
		]),
		"the image's /init chowns as root and writes under /run and /var"
	);
	assert!(
		fresh["environment"].get("CLAMAV_NO_CLAMD").is_none(),
		"only the image's /init reads CLAMAV_NO_CLAMD"
	);
}

#[test]
fn clamd_keeps_its_root_entrypoint() {
	let value = render(&minimal_answers(), false);
	let clamd = &value["services"]["clamav"];
	assert!(clamd.get("user").is_none());
	assert_eq!(clamd["entrypoint"][0], "/bin/sh");
}
