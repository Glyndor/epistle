//! The `panel` service: rendered only when the package pinned an image, with
//! the hardening of the other services, its three secrets as read-only files,
//! the mail container's network namespace and the port the mail container
//! publishes for it.

use serde_json::{Value, json};

use super::render;
use super::*;
use crate::config::{Listener, ListenerKind};

const IMAGE: &str = "ghcr.io/glyndor/epistle-panel:0.3.1";
const SECRET_NAMES: [&str; 3] = ["panel_api_token", "panel_session_secret", "panel_admin_id"];

/// A stack with the API on and the panel's image pinned.
fn panel_answers() -> crate::cli::init::Answers {
	let mut answers = stack_answers();
	answers.services.api = true;
	answers.services.panel_image = Some(IMAGE.to_string());
	answers
}

fn panel_of(value: &Value) -> &Value {
	&value["services"]["panel"]
}

fn mail_ports(value: &Value) -> Vec<String> {
	value["services"]["mail"]["ports"]
		.as_array()
		.expect("ports")
		.iter()
		.map(|port| port.as_str().expect("string").to_string())
		.collect()
}

#[test]
fn the_panel_runs_the_pinned_image_with_the_hardening_of_the_other_services() {
	let value = render(&panel_answers(), true);
	let panel = panel_of(&value);
	assert_eq!(panel["image"], IMAGE);
	assert_eq!(panel["read_only"], true);
	assert_eq!(panel["cap_drop"], json!(["ALL"]));
	assert!(
		panel.get("cap_add").is_none_or(Value::is_null),
		"the panel needs no capability back"
	);
	assert_eq!(panel["security_opt"], json!(["no-new-privileges"]));
	assert_eq!(panel["user"], "65532:65532");
	assert_eq!(panel["userns_mode"], "keep-id:uid=65532,gid=65532");
	assert_eq!(panel["tmpfs"], json!(["/tmp"]));
	assert_eq!(panel["restart"], "unless-stopped");
	assert_eq!(
		(panel["mem_limit"].clone(), panel["pids_limit"].clone()),
		(json!("512m"), json!(128)),
		"the limits come from resources.rs"
	);
	assert!(
		panel.get("privileged").is_none() && panel["volumes"] == json!([]),
		"the panel mounts no host path and is not privileged"
	);
}

#[test]
fn without_the_package_there_is_no_panel_service_secret_or_port() {
	for api in [true, false] {
		let mut answers = panel_answers();
		answers.services.api = api;
		answers.services.panel_image = None;
		let value = render(&answers, true);
		assert!(value["services"].get("panel").is_none());
		for name in SECRET_NAMES {
			assert!(value["secrets"].get(name).is_none(), "{name}");
		}
		assert!(
			mail_ports(&value).iter().all(|port| !port.contains("7587")),
			"{:?}",
			mail_ports(&value)
		);
		assert!(!serde_json::to_string(&value).unwrap().contains("panel_"));
	}
}

#[test]
fn the_panel_reaches_the_api_on_the_loopback_of_the_mail_container() {
	let value = render(&panel_answers(), true);
	let panel = panel_of(&value);
	assert_eq!(panel["network_mode"], "service:mail");
	assert_eq!(
		panel["environment"]["EPISTLE_API_URL"],
		"http://127.0.0.1:8025"
	);
	assert!(
		panel.get("ports").is_none_or(Value::is_null),
		"a container in another namespace cannot publish a port of its own"
	);
	let listeners = [Listener {
		kind: ListenerKind::Api,
		addr: "127.0.0.1".parse().unwrap(),
		port: Some(9000),
	}];
	let file = ComposeFile::build_with_nofile(&panel_answers(), Vec::new(), true, None, &listeners);
	let value: Value = serde_json::from_str(&render_document(&file).unwrap()).unwrap();
	assert_eq!(
		panel_of(&value)["environment"]["EPISTLE_API_URL"],
		"http://127.0.0.1:9000",
		"the listener's own port is the one the panel asks"
	);
}

#[test]
fn the_secrets_reach_the_panel_as_read_only_files_and_never_as_values() {
	let answers = panel_answers();
	let value = render(&answers, true);
	let secrets_dir = answers.data_dir.parent().unwrap().join("secrets");
	for name in SECRET_NAMES {
		assert_eq!(
			value["secrets"][name]["file"],
			secrets_dir.join(name).display().to_string(),
			"{name} lives beside data_dir, where mail and the backup never hold it"
		);
	}
	let mounts = panel_of(&value)["secrets"].as_array().expect("secrets");
	assert_eq!(mounts.len(), 3);
	for name in SECRET_NAMES {
		let mount = mounts
			.iter()
			.find(|mount| mount["source"] == name)
			.unwrap_or_else(|| panic!("{name} is not mounted"));
		assert_eq!(mount["target"], format!("/run/secrets/{name}"));
		assert_eq!(
			(&mount["uid"], &mount["gid"]),
			(&json!("65532"), &json!("65532"))
		);
		// 400 is the repository's spelling of mode 0400: podup reads the number as octal.
		assert_eq!(mount["mode"], json!(400));
	}
	let mail = value["services"]["mail"]["secrets"].to_string();
	assert!(
		!mail.contains("panel_"),
		"the mail service holds none of the panel's files: {mail}"
	);
}

#[test]
fn the_environment_names_the_files_and_holds_no_value_of_a_secret() {
	let value = render(&panel_answers(), true);
	let environment = panel_of(&value)["environment"].as_object().expect("env");
	let names: Vec<&str> = environment.keys().map(String::as_str).collect();
	assert_eq!(
		names,
		[
			"EPISTLE_API_TOKEN_FILE",
			"EPISTLE_API_URL",
			"EPISTLE_PANEL_ADMIN_ID_FILE",
			"EPISTLE_PANEL_SESSION_SECRET_FILE",
			"TZ",
		]
	);
	assert_eq!(
		environment["EPISTLE_API_TOKEN_FILE"],
		"/run/secrets/panel_api_token"
	);
	assert_eq!(
		environment["EPISTLE_PANEL_SESSION_SECRET_FILE"],
		"/run/secrets/panel_session_secret"
	);
	assert_eq!(
		environment["EPISTLE_PANEL_ADMIN_ID_FILE"],
		"/run/secrets/panel_admin_id"
	);
}

#[test]
fn the_healthcheck_asks_the_panels_own_port_with_the_runtimes_own_fetch() {
	let value = render(&panel_answers(), true);
	let test = panel_of(&value)["healthcheck"]["test"]
		.as_array()
		.expect("test");
	assert_eq!(test[0], "CMD", "the image has no shell to run a CMD-SHELL");
	assert_eq!(test[1], "/nodejs/bin/node");
	assert_eq!(test[2], "-e");
	let script = test[3].as_str().expect("script");
	assert!(
		script.contains("fetch('http://127.0.0.1:7587/')"),
		"{script}"
	);
	assert_eq!(test.len(), 4);
	let text = serde_json::to_string(&test).unwrap();
	assert!(!text.contains("curl") && !text.contains("wget") && !text.contains("/bin/sh"));
}

#[test]
fn the_mail_container_publishes_the_panel_port_on_loopback() {
	let value = render(&panel_answers(), true);
	let ports = mail_ports(&value);
	assert_eq!(
		ports.iter().filter(|port| port.ends_with(":7587")).count(),
		1,
		"{ports:?}"
	);
	assert!(
		ports.contains(&"127.0.0.1:7587:7587".to_string()),
		"the panel serves plain HTTP, so only the host's loopback: {ports:?}"
	);
}
