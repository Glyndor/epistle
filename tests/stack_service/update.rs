use super::helpers::*;

#[test]
fn update_restarts_the_mail_service_for_the_default_host_binary_shape() {
	// The default compose file (host binary bind-mounted on the
	// distroless base) does not pull anything: a new .deb replaces
	// the host binary and a restart of the `mail` service picks it
	// up through the bind-mount. The compose file is left
	// untouched.
	let dir = tempfile::tempdir().unwrap();
	let shim = dir.path().join("bin");
	let log = dir.path().join("argv.log");
	install_podup_shim(&shim, &recorder_shim(&log));
	let data = data_dir_with_compose(dir.path());
	let compose = data.join("compose/compose.yaml");
	let distroless = "gcr.io/distroless/static-debian12:nonroot@sha256:52dcfbabb7457ea47c82f6e13af8c8a4a1d9f7b0145142b3ecab20f2b888411d";
	std::fs::write(
		&compose,
		format!(
			r#"{{"x-epistle-managed-image":true,"services":{{"mail":{{"image":"{distroless}","volumes":["data:/data"]}}}},"volumes":{{"data":{{}}}}}}"#,
		),
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
	let expected = {
		let mut v = vec!["--version".to_string()];
		v.extend([
			"-f".to_string(),
			compose.to_str().unwrap().to_string(),
			"-f".to_string(),
			override_path.to_str().unwrap().to_string(),
			"restart".to_string(),
			"mail".to_string(),
		]);
		v
	};
	assert_eq!(
		read_argv_log(&log),
		expected,
		"default mode must restart mail, not pull or rewrite the image"
	);
	// The compose image stays at the distroless base; nothing in
	// the file moved.
	let value: serde_json::Value =
		serde_json::from_slice(&std::fs::read(compose).unwrap()).unwrap();
	assert_eq!(
		value["services"]["mail"]["image"], distroless,
		"default mode must leave the distroless image untouched"
	);
}

#[test]
fn update_pulls_then_recreates_for_a_custom_image_compose() {
	// Custom image mode keeps the previous behaviour: a `pull`
	// followed by `up -d`, so an operator that pushes a fresh
	// image gets it picked up.
	let dir = tempfile::tempdir().unwrap();
	let shim = dir.path().join("bin");
	let log = dir.path().join("argv.log");
	install_podup_shim(&shim, &recorder_shim(&log));
	let data = data_dir_with_compose(dir.path());
	let compose = data.join("compose/compose.yaml");
	std::fs::write(
		&compose,
		r#"{"x-epistle-managed-image":false,"services":{"mail":{"image":"ghcr.io/example/mail:0.9.1","volumes":["data:/data"]}},"volumes":{"data":{}}}"#,
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
	let expected = {
		let mut v = vec!["--version".to_string()];
		for extra in [
			vec!["pull".to_string()],
			vec!["up".to_string(), "-d".to_string()],
		] {
			v.extend([
				"-f".to_string(),
				compose.to_str().unwrap().to_string(),
				"-f".to_string(),
				override_path.to_str().unwrap().to_string(),
			]);
			v.extend(extra);
		}
		v
	};
	assert_eq!(
		read_argv_log(&log),
		expected,
		"custom image mode must pull then up -d"
	);
	// Custom mode does not rewrite the operator's image.
	let value: serde_json::Value =
		serde_json::from_slice(&std::fs::read(compose).unwrap()).unwrap();
	assert_eq!(
		value["services"]["mail"]["image"], "ghcr.io/example/mail:0.9.1",
		"custom mode must leave the operator's image untouched"
	);
}
