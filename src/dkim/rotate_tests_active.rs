use super::*;

fn dkim(selector: &str) -> crate::config::Dkim {
	toml::from_str(&format!(
		"selector = '{selector}'\nkey_file = '/etc/mail/configured.key'\n"
	))
	.expect("dkim config")
}

#[test]
fn without_state_the_configured_key_is_active() {
	let dir = tempfile::tempdir().expect("directory");
	let active = active_ed25519(&dkim("cfg"), dir.path()).expect("active");
	assert_eq!(active.selector, "cfg");
	assert_eq!(active.key_file, PathBuf::from("/etc/mail/configured.key"));
}

#[test]
fn relative_state_key_path_is_resolved_against_the_data_dir() {
	let dir = tempfile::tempdir().expect("directory");
	std::fs::write(
		dir.path().join(STATE_FILE),
		r#"{"selector":"ed7","key_file":"dkim-ed7.key","rotated_at":5,"previous":null}"#,
	)
	.expect("state");
	let active = active_ed25519(&dkim("cfg"), dir.path()).expect("active");
	assert_eq!(active.selector, "ed7");
	assert_eq!(active.key_file, dir.path().join("dkim-ed7.key"));
}

#[test]
fn invalid_or_empty_selector_state_is_an_error() {
	let dir = tempfile::tempdir().expect("directory");
	for content in [
		"not json",
		r#"{"selector":"","key_file":"k","rotated_at":0,"previous":null}"#,
	] {
		std::fs::write(dir.path().join(STATE_FILE), content).expect("state");
		let error = active_ed25519(&dkim("cfg"), dir.path()).expect_err("must fail");
		assert!(
			error.to_string().contains(STATE_FILE),
			"error must name the state file, got: {error}"
		);
	}
}
