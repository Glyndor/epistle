use super::{cli::fixture, stack_helpers as helpers};

#[test]
fn service_cli_compose_updates_ports_and_restarts_only_mail() {
	let (dir, config) = fixture();
	let compose = dir.path().join("compose/compose.yaml");
	std::fs::create_dir_all(compose.parent().unwrap()).unwrap();
	std::fs::write(&compose, br#"{"services":{"mail":{"image":"custom:v1","ports":["25:25","19993:19993"]},"db":{"image":"custom-db:v1"}}}"#).unwrap();
	let override_path = compose.parent().unwrap().join("compose.override.yaml");
	std::fs::write(&override_path, "services:\n  mail:\n    cpus: 2\n").unwrap();
	let override_bytes = std::fs::read(&override_path).unwrap();
	let shim_dir = dir.path().join("bin");
	let argv_log = dir.path().join("argv.log");
	std::fs::write(&argv_log, "").unwrap();
	helpers::install_podup_shim(&shim_dir, &helpers::recorder_shim(&argv_log));
	let output = helpers::run_with_podup(
		&[
			"service",
			"enable",
			"imap",
			"--config",
			config.to_str().unwrap(),
		],
		&shim_dir,
	);
	assert_eq!(output.status.code(), Some(0));
	let after: serde_json::Value =
		serde_json::from_slice(&std::fs::read(&compose).unwrap()).unwrap();
	assert_eq!(
		after["services"]["mail"]["ports"],
		serde_json::json!(["25:25", "19993:19993", "143:143"]),
		"CLI must publish exactly the new listener set"
	);
	assert_eq!(
		helpers::read_argv_log(&argv_log),
		[
			"--version",
			"-f",
			compose.to_str().unwrap(),
			"-f",
			override_path.to_str().unwrap(),
			"restart",
			"mail"
		],
		"service edit must use stack restart for only mail"
	);
	assert!(std::fs::read(&override_path).unwrap() == override_bytes);
	let argv_before = std::fs::read(&argv_log).unwrap();
	let noop = helpers::run_with_podup(
		&[
			"service",
			"--config",
			config.to_str().unwrap(),
			"enable",
			"imap",
		],
		&shim_dir,
	);
	assert_eq!(noop.status.code(), Some(0));
	assert!(
		std::fs::read(&argv_log).unwrap() == argv_before,
		"no-op must not restart the stack"
	);
	let output = helpers::run_with_podup(
		&[
			"service",
			"--config",
			config.to_str().unwrap(),
			"disable",
			"imaps",
		],
		&shim_dir,
	);
	assert_eq!(output.status.code(), Some(0));
	let after: serde_json::Value =
		serde_json::from_slice(&std::fs::read(&compose).unwrap()).unwrap();
	assert_eq!(
		after["services"]["mail"]["ports"],
		serde_json::json!(["25:25", "143:143"]),
		"disabling IMAPS must leave IMAP published"
	);
	assert!(std::fs::read(&override_path).unwrap() == override_bytes);
}
