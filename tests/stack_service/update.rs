use super::helpers::*;

#[test]
fn update_pulls_then_recreates_with_the_existing_override() {
	let dir = tempfile::tempdir().unwrap();
	let shim = dir.path().join("bin");
	let log = dir.path().join("argv.log");
	install_podup_shim(&shim, &recorder_shim(&log));
	let data = data_dir_with_compose(dir.path());
	let compose = data.join("compose/compose.yaml");
	std::fs::write(
		&compose,
		r#"{"x-epistle-managed-image":true,"services":{"mail":{"image":"ghcr.io/glyndor/epistle:0.7"}}}"#,
	)
	.unwrap();
	let override_path = compose.with_file_name("compose.override.yaml");
	std::fs::write(&override_path, "services:\n  mail:\n    mem_limit: 1g\n").unwrap();
	let cfg = write_config(&data);
	let out = run_with_podup(
		&["stack", "--config", cfg.to_str().unwrap(), "update"],
		&shim,
	);
	assert_eq!(
		out.status.code(),
		Some(0),
		"stack update must be accepted and complete"
	);
	let mut expected = vec!["--version"];
	for extra in [vec!["pull"], vec!["up", "-d"]] {
		expected.extend([
			"-f",
			compose.to_str().unwrap(),
			"-f",
			override_path.to_str().unwrap(),
		]);
		expected.extend(extra);
	}
	assert_eq!(
		read_argv_log(&log),
		expected,
		"update must pull before recreating the stack with both compose files"
	);
	let value: serde_json::Value =
		serde_json::from_slice(&std::fs::read(compose).unwrap()).unwrap();
	assert_eq!(
		value["services"]["mail"]["image"],
		format!("ghcr.io/glyndor/epistle:{}", env!("CARGO_PKG_VERSION")),
		"update must persist the current CLI image before podup runs"
	);
}
