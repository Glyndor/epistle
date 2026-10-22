use super::{cli::fixture, stack_helpers as helpers};

#[test]
fn service_cli_compose_updates_ports_and_recreates_only_mail() {
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
			"up",
			"-d",
			"mail"
		],
		"a port change must recreate only mail"
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

/// A generated compose file with `mail` publishing `mappings`, next to the
/// operator override in `override_text`.
fn stack(
	dir: &std::path::Path,
	mappings: &[&str],
	override_text: &str,
) -> (std::path::PathBuf, Vec<u8>) {
	let compose = dir.join("compose/compose.yaml");
	std::fs::create_dir_all(compose.parent().unwrap()).unwrap();
	std::fs::write(
		&compose,
		serde_json::to_vec(&serde_json::json!({
			"services": {"mail": {"image": "custom:v1", "ports": mappings}}
		}))
		.unwrap(),
	)
	.unwrap();
	let override_path = compose.parent().unwrap().join("compose.override.yaml");
	std::fs::write(&override_path, override_text).unwrap();
	let bytes = std::fs::read(&override_path).unwrap();
	(compose, bytes)
}

/// The `ports:` array of the `mail` service in the generated file.
fn ports(compose: &std::path::Path) -> serde_json::Value {
	serde_json::from_slice::<serde_json::Value>(&std::fs::read(compose).unwrap()).unwrap()
		["services"]["mail"]["ports"]
		.clone()
}

#[test]
fn service_set_publishes_on_the_address_the_operator_asked_for() {
	let (dir, config) = fixture();
	let (compose, override_bytes) = stack(
		dir.path(),
		&["25:25", "19993:19993"],
		"services:\n  mail:\n    cpus: 2\n",
	);
	let shim_dir = dir.path().join("bin");
	let argv_log = dir.path().join("argv.log");
	std::fs::write(&argv_log, "").unwrap();
	helpers::install_podup_shim(&shim_dir, &helpers::recorder_shim(&argv_log));
	let output = helpers::run_with_podup(
		&[
			"service",
			"--config",
			config.to_str().unwrap(),
			"set",
			"imaps",
			"--bind",
			"127.0.0.1",
		],
		&shim_dir,
	);
	assert_eq!(
		output.status.code(),
		Some(0),
		"{}",
		String::from_utf8_lossy(&output.stderr)
	);
	assert_eq!(
		String::from_utf8(output.stderr).unwrap(),
		"imaps published on 127.0.0.1:19993.\n"
	);
	assert_eq!(
		ports(&compose),
		serde_json::json!(["25:25", "127.0.0.1:19993:19993"]),
		"the host side of the mapping is the address the operator asked for"
	);
	let cfg = epistle::config::Config::load(&config).unwrap();
	let imaps = &cfg.listeners[1];
	assert_eq!(
		imaps.addr.to_string(),
		"0.0.0.0",
		"inside the container the listener binds every address, or the mapping cannot reach it"
	);
	assert_eq!(imaps.socket_addr().port(), 19993, "the port does not move");
	assert!(
		std::fs::read(compose.parent().unwrap().join("compose.override.yaml")).unwrap()
			== override_bytes,
		"the operator override is never written"
	);
	assert_eq!(
		helpers::read_argv_log(&argv_log).last().map(String::as_str),
		Some("mail"),
		"a mapping that moved recreates mail"
	);
	let before = std::fs::read(&argv_log).unwrap();
	let again = helpers::run_with_podup(
		&[
			"service",
			"--config",
			config.to_str().unwrap(),
			"set",
			"imaps",
			"--bind",
			"127.0.0.1",
		],
		&shim_dir,
	);
	assert_eq!(again.status.code(), Some(0));
	assert_eq!(
		String::from_utf8(again.stderr).unwrap(),
		"imaps is already published on 127.0.0.1:19993; nothing changed.\n"
	);
	assert!(
		std::fs::read(&argv_log).unwrap() == before,
		"the same request must not restart the stack"
	);
}

#[test]
fn service_set_keeps_the_port_when_only_the_address_moves() {
	let (dir, config) = fixture();
	let (compose, _) = stack(dir.path(), &["25:25", "19993:19993"], "");
	let shim_dir = dir.path().join("bin");
	let argv_log = dir.path().join("argv.log");
	std::fs::write(&argv_log, "").unwrap();
	helpers::install_podup_shim(&shim_dir, &helpers::recorder_shim(&argv_log));
	let output = helpers::run_with_podup(
		&[
			"service",
			"--config",
			config.to_str().unwrap(),
			"set",
			"imaps",
			"--port",
			"19994",
		],
		&shim_dir,
	);
	assert_eq!(
		output.status.code(),
		Some(0),
		"{}",
		String::from_utf8_lossy(&output.stderr)
	);
	assert_eq!(
		ports(&compose),
		serde_json::json!(["25:25", "19994:19994"]),
		"a port with no host address keeps the form init writes"
	);
	assert_eq!(
		epistle::config::Config::load(&config).unwrap().listeners[1]
			.socket_addr()
			.port(),
		19994
	);
}

#[test]
fn service_set_takes_the_pinned_address_with_the_port() {
	let (dir, config) = fixture();
	let (compose, _) = stack(dir.path(), &["25:25", "19993:19993"], "");
	let shim_dir = dir.path().join("bin");
	let argv_log = dir.path().join("argv.log");
	std::fs::write(&argv_log, "").unwrap();
	helpers::install_podup_shim(&shim_dir, &helpers::recorder_shim(&argv_log));
	let set = |args: &[&str]| {
		let mut full = vec!["service", "--config", config.to_str().unwrap(), "set"];
		full.extend_from_slice(args);
		let output = helpers::run_with_podup(&full, &shim_dir);
		assert_eq!(
			output.status.code(),
			Some(0),
			"{args:?}: {}",
			String::from_utf8_lossy(&output.stderr)
		);
	};
	set(&["imaps", "--bind", "10.0.0.5"]);
	assert_eq!(
		ports(&compose),
		serde_json::json!(["25:25", "10.0.0.5:19993:19993"])
	);
	// The port moves alone, and the address the operator pinned comes with it
	// instead of falling back to every host address.
	set(&["imaps", "--port", "19994"]);
	assert_eq!(
		ports(&compose),
		serde_json::json!(["25:25", "10.0.0.5:19994:19994"])
	);
	assert_eq!(
		epistle::config::Config::load(&config).unwrap().listeners[1]
			.socket_addr()
			.port(),
		19994
	);
}

#[test]
fn service_set_says_the_operator_override_wins_and_touches_nothing() {
	let (dir, config) = fixture();
	let (compose, override_bytes) = stack(
		dir.path(),
		&["25:25", "19993:19993"],
		"services:\n  mail:\n    ports: !override\n      - \"25:25\"\n      - \"10.0.0.9:19993:19993\"\n",
	);
	let shim_dir = dir.path().join("bin");
	let argv_log = dir.path().join("argv.log");
	std::fs::write(&argv_log, "").unwrap();
	helpers::install_podup_shim(&shim_dir, &helpers::recorder_shim(&argv_log));
	let output = helpers::run_with_podup(
		&[
			"service",
			"--config",
			config.to_str().unwrap(),
			"set",
			"imaps",
			"--bind",
			"127.0.0.1",
		],
		&shim_dir,
	);
	assert_eq!(output.status.code(), Some(0));
	let stderr = String::from_utf8(output.stderr).unwrap();
	assert!(
		stderr.contains("imaps published on 127.0.0.1:19993.")
			&& stderr.contains("compose.override.yaml publishes a port for mail, and it wins"),
		"the operator has to hear which mapping answers: {stderr}"
	);
	assert_eq!(
		ports(&compose),
		serde_json::json!(["25:25", "127.0.0.1:19993:19993"])
	);
	assert!(
		std::fs::read(compose.parent().unwrap().join("compose.override.yaml")).unwrap()
			== override_bytes,
		"the override stays exactly as the operator wrote it"
	);
}

#[test]
fn service_list_names_the_host_address_the_map_pins() {
	let (dir, config) = fixture();
	let (compose, _) = stack(dir.path(), &["25:25", "19993:19993"], "");
	let shim_dir = dir.path().join("bin");
	let argv_log = dir.path().join("argv.log");
	std::fs::write(&argv_log, "").unwrap();
	helpers::install_podup_shim(&shim_dir, &helpers::recorder_shim(&argv_log));
	let set = helpers::run_with_podup(
		&[
			"service",
			"--config",
			config.to_str().unwrap(),
			"set",
			"imaps",
			"--bind",
			"127.0.0.1",
		],
		&shim_dir,
	);
	assert_eq!(
		set.status.code(),
		Some(0),
		"the setup has to land: {}",
		String::from_utf8_lossy(&set.stderr)
	);
	assert_eq!(
		ports(&compose),
		serde_json::json!(["25:25", "127.0.0.1:19993:19993"])
	);
	let table = String::from_utf8(
		helpers::run_with_podup(
			&["service", "--config", config.to_str().unwrap(), "list"],
			&shim_dir,
		)
		.stdout,
	)
	.unwrap();
	let lines: Vec<&str> = table.lines().collect();
	assert!(
		lines[0]
			.split_whitespace()
			.eq(["SERVICE", "STATE", "PORT", "BIND", "HOST"]),
		"the host column is there: {lines:?}"
	);
	assert!(
		lines
			.iter()
			.any(|line| line.split_whitespace().collect::<Vec<_>>()
				== ["imaps", "enabled", "19993", "0.0.0.0", "127.0.0.1"]),
		"the row names the host address: {lines:?}"
	);
	assert!(
		lines
			.iter()
			.any(|line| line.split_whitespace().collect::<Vec<_>>()
				== ["smtp", "enabled", "25", "::", "-"]),
		"a mapping nobody narrowed shows no address: {lines:?}"
	);
	let json: serde_json::Value = serde_json::from_slice(
		&helpers::run_with_podup(
			&[
				"service",
				"--config",
				config.to_str().unwrap(),
				"list",
				"--json",
			],
			&shim_dir,
		)
		.stdout,
	)
	.unwrap();
	let imaps = json
		.as_array()
		.unwrap()
		.iter()
		.find(|row| row["name"] == "imaps")
		.unwrap();
	assert_eq!(imaps["host"], "127.0.0.1");
	assert_eq!(
		imaps["bind"], "0.0.0.0",
		"the bind is the container-side one"
	);
	assert!(
		json.as_array()
			.unwrap()
			.iter()
			.all(|row| row.get("host").is_none() || row["name"] == "imaps"),
		"only the pinned mapping carries a host: {json}"
	);
}

#[test]
fn a_dry_run_names_the_mapping_it_would_move_and_writes_nothing() {
	let (dir, config) = fixture();
	let (compose, _) = stack(dir.path(), &["25:25", "19993:19993"], "");
	let shim_dir = dir.path().join("bin");
	let argv_log = dir.path().join("argv.log");
	std::fs::write(&argv_log, "").unwrap();
	helpers::install_podup_shim(&shim_dir, &helpers::recorder_shim(&argv_log));
	let output = helpers::run_with_podup(
		&[
			"service",
			"--config",
			config.to_str().unwrap(),
			"--dry-run",
			"set",
			"imaps",
			"--bind",
			"127.0.0.1",
		],
		&shim_dir,
	);
	assert_eq!(
		output.status.code(),
		Some(0),
		"{}",
		String::from_utf8_lossy(&output.stderr)
	);
	let stdout = String::from_utf8(output.stdout).unwrap();
	assert!(
		stdout.contains("- 19993:19993") && stdout.contains("+ 127.0.0.1:19993:19993"),
		"the mapping that would move is the part the config diff does not carry: {stdout}"
	);
	assert_eq!(
		ports(&compose),
		serde_json::json!(["25:25", "19993:19993"]),
		"a dry run writes nothing"
	);
	assert_eq!(
		helpers::read_argv_log(&argv_log),
		Vec::<String>::new(),
		"a dry run does not restart the stack"
	);
}
