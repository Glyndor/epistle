//! The hook `stack update` runs: the panel's secrets are created with the
//! other keys when the new stack runs the panel, and not otherwise.

use super::*;
use crate::cli::init::prepare_keys_for_update;

/// A config file `prepare_keys_for_update` can read.
fn config(layout: &Layout) -> PathBuf {
	use std::os::unix::fs::PermissionsExt;
	let path = layout.data.parent().expect("parent").join("mail.toml");
	std::fs::write(&path, "[storage]\n").expect("config");
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
	path
}

#[test]
fn an_update_for_a_stack_with_the_panel_creates_its_secrets_and_says_so() {
	let layout = layout();
	let config = config(&layout);
	let lines =
		prepare_keys_for_update(&layout.data, &config, false, false, true).expect("prepare");
	for path in paths(&layout.data) {
		assert!(path.is_file(), "{path:?}");
		assert!(
			lines.contains(&format!("created {}", path.display())),
			"{lines:?}"
		);
	}
	assert_eq!(row(&layout).scopes, ["read", "write"]);
}

#[test]
fn an_update_for_a_stack_without_the_panel_creates_nothing_of_it() {
	let layout = layout();
	let config = config(&layout);
	prepare_keys_for_update(&layout.data, &config, false, false, false).expect("prepare");
	for path in paths(&layout.data) {
		assert!(!path.exists(), "{path:?}");
	}
	assert_eq!(count_keys(&layout), 0);
}

#[test]
fn a_second_update_changes_nothing_and_says_nothing_about_the_panel() {
	let layout = layout();
	let config = config(&layout);
	prepare_keys_for_update(&layout.data, &config, false, false, true).expect("first");
	let before = (text(&api_token_path(&layout.data)), row(&layout).hash);
	let lines = prepare_keys_for_update(&layout.data, &config, false, false, true).expect("second");
	assert!(
		lines.iter().all(|line| !line.contains("panel")),
		"{lines:?}"
	);
	assert_eq!(
		(text(&api_token_path(&layout.data)), row(&layout).hash),
		before
	);
}

#[test]
fn an_update_that_renews_the_key_tells_the_operator_the_file_was_replaced() {
	let layout = layout();
	let config = config(&layout);
	prepare_keys_for_update(&layout.data, &config, false, false, true).expect("first");
	// Move the key's deadline to 10 days from the real clock.
	let mut store = ApiKeyStore::open(&layout.data).expect("open");
	let soon = now() + 10 * DAY;
	store
		.renew(LABEL, row(&layout).hash, soon)
		.expect("shorten");
	let lines = prepare_keys_for_update(&layout.data, &config, false, false, true).expect("renew");
	assert!(
		lines.contains(&format!(
			"replaced {}",
			api_token_path(&layout.data).display()
		)),
		"{lines:?}"
	);
	assert!(row(&layout).expires_at.expect("expiry") > soon);
}

#[test]
fn a_refused_panel_secret_fails_the_update_before_any_podup_step() {
	let layout = layout();
	let config = config(&layout);
	std::fs::create_dir_all(api_token_path(&layout.data)).expect("dir");
	let error =
		prepare_keys_for_update(&layout.data, &config, false, false, true).expect_err("refused");
	assert!(error.contains("path is not a regular file"), "{error}");
}
