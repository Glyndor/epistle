//! A new installation starts with a secret of its own for each domain's
//! forwarded mail; an installation that exists is left as its operator has it.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use super::*;
use crate::cli::init::answers::{Answers, Mode, Services};
use crate::config::Config;

fn answers_for(dir: &std::path::Path, domains: &[&str]) -> Answers {
	Answers {
		mode: Mode::Manual,
		hostname: "mail.example.org".to_string(),
		domains: domains.iter().map(|d| (*d).to_string()).collect(),
		public_ipv4: Some(std::net::Ipv4Addr::new(8, 8, 8, 8)),
		public_ipv6: None,
		data_dir: dir.join("data"),
		config_path: dir.join("mail.toml"),
		dns: None,
		services: Services::default(),
		image: Some("localhost/epistle:dev".to_string()),
		acme: None,
		first_account: None,
		resources: Default::default(),
	}
}

#[test]
fn a_new_install_writes_a_different_secret_for_each_domain() {
	let dir = tempfile::tempdir().expect("tempdir");
	let answers = answers_for(dir.path(), &["a.example", "b.example"]);
	let outcome = apply(&answers);
	assert!(outcome.error.is_none(), "apply failed: {:?}", outcome.error);
	drop(outcome);
	let config = Config::load(&answers.config_path).expect("the written file loads");
	let a = config
		.srs_domain("a.example")
		.expect("an entry for a.example");
	let b = config
		.srs_domain("b.example")
		.expect("an entry for b.example");
	assert_eq!(a.secret.len(), 43);
	assert_ne!(a.secret, b.secret, "two domains were given one secret");
	assert!(
		config.srs_secret.is_none(),
		"no server-wide secret is written"
	);
	assert!(config.srs_notices().is_empty());
}

#[test]
fn a_rerun_leaves_the_secrets_of_an_existing_install_alone() {
	let dir = tempfile::tempdir().expect("tempdir");
	let answers = answers_for(dir.path(), &["a.example"]);
	assert!(apply(&answers).error.is_none());
	let first = std::fs::read_to_string(&answers.config_path).expect("read");
	assert!(apply(&answers).error.is_none());
	let second = std::fs::read_to_string(&answers.config_path).expect("read");
	assert_eq!(first, second, "a re-run rewrote the secrets");
}

#[test]
fn init_over_an_existing_file_does_not_add_secrets_to_it() {
	let dir = tempfile::tempdir().expect("tempdir");
	let answers = answers_for(dir.path(), &["a.example"]);
	let path: PathBuf = answers.config_path.clone();
	let secret = crate::test_support::fixtures::fresh_secret();
	std::fs::write(
		&path,
		format!(
			"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\n\
			 domains = [\"a.example\"]\nsrs_secret = \"{secret}\"\n",
			answers.data_dir.display()
		),
	)
	.expect("write");
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
	let outcome = apply(&answers);
	assert!(outcome.error.is_none(), "apply failed: {:?}", outcome.error);
	drop(outcome);
	let config = Config::load(&path).expect("loads");
	assert!(
		config.srs_domain.is_empty(),
		"init split an existing install"
	);
	assert_eq!(config.srs_secret.as_deref(), Some(secret.as_str()));
}
