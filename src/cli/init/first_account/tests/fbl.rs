//! The complaint mailbox `init` offers: never assumed, and when asked for, an
//! alias of the first account named in `[reports]`.

use super::*;

fn domains() -> Vec<String> {
	vec!["example.org".to_string()]
}

fn account(fbl: Option<&str>) -> FirstAccount {
	FirstAccount {
		address: "alice@example.org".to_string(),
		display_name: None,
		password_file: None,
		role_aliases: false,
		fbl_mailbox: fbl.map(str::to_string),
	}
}

#[test]
fn no_complaint_mailbox_is_assumed() {
	let first = account(None);
	assert_eq!(first.fbl_address(), None);
	assert_eq!(first.fbl_alias(), None);
	let parsed: FirstAccount = toml::from_str("address = \"alice@example.org\"").expect("parse");
	assert_eq!(parsed.fbl_mailbox, None);
}

#[test]
fn the_mailbox_must_be_a_plain_address_of_a_configured_domain() {
	account(Some("Fbl@Example.org"))
		.check(&domains())
		.expect("a hosted address is accepted");
	for bad in ["fbl", "fbl@elsewhere.example", "Reports <fbl@example.org>"] {
		let why = account(Some(bad)).check(&domains()).expect_err(bad);
		assert!(
			why.contains("fbl_mailbox"),
			"the refusal must name the fbl_mailbox setting"
		);
	}
}

#[test]
fn an_alias_is_not_made_for_the_account_itself() {
	let own = account(Some("alice@example.org"));
	assert_eq!(own.fbl_address().as_deref(), Some("alice@example.org"));
	assert_eq!(own.fbl_alias(), None);
	assert_eq!(
		account(Some("FBL@example.org")).fbl_alias().as_deref(),
		Some("fbl@example.org")
	);
}

#[test]
fn the_mailbox_becomes_an_alias_and_is_named_in_reports() {
	use std::os::unix::fs::PermissionsExt;
	let dir = tempfile::tempdir().expect("tempdir");
	let config_path = dir.path().join("mail.toml");
	std::fs::write(
		&config_path,
		format!(
			"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\ndomains = [\"example.org\"]\n",
			dir.path().join("data").display()
		),
	)
	.expect("write config");
	std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
	std::fs::create_dir_all(dir.path().join("data")).expect("data dir");
	let mut report = Report::default();
	add_fbl_mailbox(
		&account(Some("fbl@example.org")),
		&config_path,
		"alice@example.org",
		&mut report,
	)
	.expect("complaint mailbox");
	let config = Config::load(&config_path).expect("the written file loads");
	assert_eq!(
		config.reports.fbl_mailbox.as_deref(),
		Some("fbl@example.org")
	);
	assert!(
		config.reports.fbl_senders.is_empty(),
		"nobody is trusted yet"
	);
	assert_eq!(config.alias.len(), 1);
	assert_eq!(config.alias[0].address, "fbl@example.org");
}

#[test]
fn without_a_mailbox_the_configuration_is_left_alone() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config_path = dir.path().join("mail.toml");
	let mut report = Report::default();
	add_fbl_mailbox(
		&account(None),
		&config_path,
		"alice@example.org",
		&mut report,
	)
	.expect("nothing to do");
	assert!(!config_path.exists());
	assert!(report.steps.is_empty());
}
