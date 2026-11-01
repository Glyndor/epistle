use super::helpers::*;

#[test]
fn up_installs_autostart_after_starting_the_stack() {
	check_sequence("up", &["up", "-d"], &["autostart", "install"]);
}

#[test]
fn down_uninstalls_autostart_before_stopping_the_stack() {
	check_sequence("down", &["autostart", "uninstall"], &["down"]);
}

fn check_sequence(action: &str, first: &[&str], second: &[&str]) {
	let dir = tempfile::tempdir().unwrap();
	let shim = dir.path().join("bin");
	let log = dir.path().join("argv.log");
	install_podup_shim(&shim, &recorder_shim(&log));
	let data = data_dir_with_compose(dir.path());
	let cfg = write_config(&data);
	let (out, argv) = run_streaming(
		&["stack", "--config", cfg.to_str().unwrap(), action],
		&shim,
		&log,
	);
	assert_eq!(
		out.status.code(),
		Some(0),
		"stack must propagate successful podup commands"
	);
	let compose = data.join("compose/compose.yaml");
	let mut expected = vec!["--version", "-f", compose.to_str().unwrap()];
	expected.extend(first);
	expected.extend(["-f", compose.to_str().unwrap()]);
	expected.extend(second);
	assert_eq!(
		argv, expected,
		"stack must run both lifecycle commands in the required order"
	);
}
