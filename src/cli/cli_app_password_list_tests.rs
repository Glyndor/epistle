//! `epistle app-password list`: the `--account` filter and the output
//! shape, read back from a real `AppPasswordStore`.

use std::process::ExitCode;

use crate::cli::app_passwords::{AppPasswordCli, run};
use crate::config::Config;
use crate::directory_store::{AppPassword, AppPasswordStore};

/// A config over `data_dir` with app passwords for bob and carol.
fn seeded(data_dir: &std::path::Path) -> Config {
	let mut store = AppPasswordStore::open(data_dir).expect("open store");
	for (account, label) in [("bob", "phone"), ("carol", "laptop")] {
		store
			.add(
				account,
				AppPassword {
					label: label.to_string(),
					hash: crate::smtp::auth::tests::base::hash(crate::test_fixtures::password()),
					expires_at: None,
					ip_cidr: None,
					save_sent: None,
				},
			)
			.expect("add app password");
	}
	toml::from_str(&format!(
		"hostname = \"mail.example.org\"\ndata_dir = {data_dir:?}\n"
	))
	.expect("config")
}

fn listed(config: &Config, action: AppPasswordCli) -> String {
	let mut out = Vec::new();
	assert_eq!(run(config, action, false, &mut out), ExitCode::SUCCESS);
	String::from_utf8(out).expect("utf8")
}

#[test]
fn list_with_account_shows_only_that_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = seeded(dir.path());
	let text = listed(
		&config,
		AppPasswordCli::List {
			account: Some("bob".to_string()),
			json: false,
		},
	);
	assert_eq!(
		text,
		"bob\tphone\texpires=never\tip=any\tsave_sent=default\n"
	);
}

#[test]
fn list_without_account_shows_every_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = seeded(dir.path());
	let text = listed(
		&config,
		AppPasswordCli::List {
			account: None,
			json: false,
		},
	);
	assert_eq!(
		text,
		"bob\tphone\texpires=never\tip=any\tsave_sent=default\ncarol\tlaptop\texpires=never\tip=any\tsave_sent=default\n"
	);
}
