//! The `panel` container: made again after its key when the stack runs it.

use super::super::super::steps::{self, Context};
use super::*;

/// The one stack action a run that rotated the panel's key asks for.
const RECREATE: &str = "Recreate { service: \"panel\" }";

#[test]
fn a_stack_that_runs_the_panel_makes_its_container_again_after_the_key() {
	let install = install_with_panel();
	compose(&install, &["mail", "panel"]);
	let ran = run(&install.config, NOW, true, ExitCode::SUCCESS);
	assert_eq!(ran.code, ExitCode::SUCCESS, "{}", ran.status);
	assert_eq!(
		kinds(&ran.out),
		["api-key", "panel-api-key", "panel-recreate"]
	);
	// Made again, not restarted: a restart keeps the secret the container
	// was created with.
	assert_eq!(ran.actions, [RECREATE]);
	assert!(file_is_the_stored_key(&install));
	let result: serde_json::Value = serde_json::from_str(&ran.out).unwrap();
	assert_eq!(result["steps"][2]["result"], "restarted");
}

/// A server with an app password, a webhook secret and the panel: the
/// container is the last thing the run touches, after the mail restart.
#[test]
fn the_container_is_made_again_after_every_secret_and_the_mail_restart() {
	let install = install_with_panel();
	compose(&install, &["mail", "panel"]);
	app_password(&install);
	let minted = crate::queue::srs::generate_secret().unwrap();
	let mut text = std::fs::read_to_string(&install.config).unwrap();
	text.push_str(&format!(
		"\n[webhook]\nurl = 'https://hooks.example.net/epistle'\nsecret = '{minted}'\n"
	));
	std::fs::write(&install.config, text).unwrap();
	let ran = run(&install.config, NOW, true, ExitCode::SUCCESS);
	assert_eq!(ran.code, ExitCode::SUCCESS, "{}", ran.status);
	assert_eq!(
		kinds(&ran.out),
		[
			"api-key",
			"panel-api-key",
			"app-password",
			"webhook-secret",
			"restart",
			"panel-recreate"
		]
	);
	assert_eq!(
		ran.actions,
		["Restart { service: Some(\"mail\") }", RECREATE]
	);
}

/// A run stops at its first failure, so a panel that cannot be made again
/// must come after every secret: none is left with its old value for it.
#[test]
fn a_container_that_cannot_be_made_again_keeps_no_secret_from_being_rotated() {
	let install = install_with_panel();
	compose(&install, &["mail", "panel"]);
	let before = app_password(&install);
	let failed = run(&install.config, NOW, true, ExitCode::FAILURE);
	assert_eq!(failed.code, ExitCode::FAILURE);
	assert_eq!(failed.actions, [RECREATE]);
	assert!(
		app_password_hash(&install) != before,
		"the app password kept its old secret"
	);
}

#[test]
fn a_stack_without_the_panel_service_is_left_alone_and_the_file_is_still_written() {
	for services in [&["mail"][..], &["mail", "panels"][..]] {
		let install = install_with_panel();
		compose(&install, services);
		let ran = run(&install.config, NOW, true, ExitCode::SUCCESS);
		assert_eq!(ran.code, ExitCode::SUCCESS, "{}", ran.status);
		assert_eq!(kinds(&ran.out), ["api-key", "panel-api-key"]);
		assert!(ran.actions.is_empty(), "{:?}", ran.actions);
		assert!(file_is_the_stored_key(&install));
	}
}

#[test]
fn a_container_that_cannot_be_made_again_stops_the_run_and_the_next_one_asks_again() {
	let install = install_with_panel();
	compose(&install, &["mail", "panel"]);
	let failed = run(&install.config, NOW, true, ExitCode::FAILURE);
	assert_eq!(failed.code, ExitCode::FAILURE);
	assert_eq!(failed.actions, [RECREATE]);
	assert!(failed.out.is_empty(), "{}", failed.out);
	// The key and the file are done and agree; only the container is left.
	assert!(file_is_the_stored_key(&install));
	let rotated = stored(&install, "panel");
	assert!(install.data.join("rotate/journal.json").exists());
	let ran = run(&install.config, NOW + 60, true, ExitCode::SUCCESS);
	assert_eq!(ran.code, ExitCode::SUCCESS, "{}", ran.status);
	assert_eq!(ran.actions, [RECREATE]);
	assert_eq!(
		stored(&install, "panel"),
		rotated,
		"the key was rotated a second time"
	);
	assert!(file_is_the_stored_key(&install));
}

#[test]
fn a_compose_file_that_cannot_be_read_refuses_the_run_before_anything_changes() {
	let install = install_with_panel();
	let path = crate::cli::init::compose_file_path(&install.data);
	std::fs::create_dir_all(path.parent().unwrap()).unwrap();
	std::fs::write(&path, b"services: [").unwrap();
	let before = stored(&install, "panel");
	let config = Config::load(&install.config).unwrap();
	let context = Context {
		path: &install.config,
		config: &config,
		now: NOW,
	};
	let refusal = steps::plan(&context).expect_err("a plan was made");
	assert!(
		refusal.contains("whether the panel container has to be made again"),
		"{refusal}"
	);
	let ran = run(&install.config, NOW, true, ExitCode::SUCCESS);
	assert_eq!(ran.code, ExitCode::FAILURE);
	assert_eq!(stored(&install, "panel"), before);
	assert!(file_is_the_stored_key(&install));
}

#[test]
fn the_refusal_of_a_link_names_the_file_and_the_reason() {
	let install = install_with_panel();
	let path = key_file(&install);
	let elsewhere = path.with_file_name("elsewhere");
	std::fs::rename(&path, &elsewhere).unwrap();
	std::os::unix::fs::symlink(&elsewhere, &path).unwrap();
	let config = Config::load(&install.config).unwrap();
	let context = Context {
		path: &install.config,
		config: &config,
		now: NOW,
	};
	let refusal = steps::plan(&context).expect_err("a plan was made");
	assert!(refusal.contains("panel_api_token"), "{refusal}");
	assert!(refusal.contains("symlink"), "{refusal}");
	let secret = std::fs::read_to_string(&elsewhere).unwrap();
	assert!(
		!refusal.contains(secret.trim()),
		"the refusal shows the key"
	);
}
