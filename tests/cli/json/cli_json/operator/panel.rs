//! `panel admin-id`, and that no other command's JSON carries the id.

use serde_json::Value;

use crate::harness::{Env, PASSWORD, env, epistle};

const ID: &str = "3f2b8c1e-5d4a-4b7e-9c3d-1a2b3c4d5e6f";

/// The id file beside the data directory, as `init` leaves it.
fn place_id(env: &Env) {
	let secrets = env.dir.path().join("secrets");
	std::fs::create_dir_all(&secrets).expect("secrets dir");
	std::fs::write(secrets.join("panel_admin_id"), ID).expect("write id");
}

#[test]
fn the_id_is_shown_as_one_object_with_the_path() {
	let env = env("");
	place_id(&env);
	let output = epistle(
		&["panel", "admin-id", "--config", &env.config, "--json"],
		b"",
	);
	assert_eq!(output.status.code(), Some(0));
	let value: Value = serde_json::from_slice(&output.stdout).expect("one document");
	assert_eq!(value["admin_id"], ID);
	assert_eq!(value["path"], format!("/app/{ID}"));
}

#[test]
fn the_plain_form_keeps_stdout_to_the_id_alone() {
	let env = env("");
	place_id(&env);
	let output = epistle(&["panel", "admin-id", "--config", &env.config], b"");
	assert_eq!(output.status.code(), Some(0));
	assert_eq!(String::from_utf8_lossy(&output.stdout), format!("{ID}\n"));
	assert!(String::from_utf8_lossy(&output.stderr).contains("do not publish"));
}

#[test]
fn no_other_command_prints_the_id_on_either_stream() {
	let env = env("srs_secret = \"0123456789abcdef0123456789abcdef\"\n");
	place_id(&env);
	for args in [
		vec!["config-check"],
		vec!["verify"],
		vec!["account", "list"],
		vec!["rotate", "--all", "--dry-run"],
		vec!["srs", "show"],
		vec!["api-key", "list"],
	] {
		let mut full = args.clone();
		full.extend(["--config", &env.config, "--json"]);
		let output = epistle(&full, PASSWORD);
		let shown = format!(
			"{}{}",
			String::from_utf8_lossy(&output.stdout),
			String::from_utf8_lossy(&output.stderr)
		);
		assert!(
			!shown.contains(ID),
			"{args:?} printed the admin id: {shown}"
		);
	}
}
