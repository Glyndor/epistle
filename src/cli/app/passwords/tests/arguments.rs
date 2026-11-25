//! A value `app-password create` cannot take is a usage error, exit code 2,
//! whatever the data directory holds, and nothing is bound or stored before
//! it is refused.

use crate::cli::app::passwords::tests::*;
use crate::directory_store::AppPasswordStore;

fn config(data_dir: &std::path::Path) -> Config {
	let toml = format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\n",
		data_dir.display()
	);
	toml::from_str(&toml).expect("config parses")
}

fn seed_account(data_dir: &std::path::Path) {
	std::fs::write(
		data_dir.join("accounts.toml"),
		"[[accounts]]\nname = \"alice\"\naddresses = [\"alice@example.org\"]\npassword_hash = \"stub\"\n",
	)
	.expect("write accounts.toml");
}

#[allow(clippy::too_many_arguments)]
fn create_with(
	config: &Config,
	account: &str,
	(cidr, save_sent): (Option<&str>, Option<&str>),
	class: Option<crate::evidence::MailClass>,
) -> ExitCode {
	create(
		config,
		account,
		"phone",
		None,
		cidr.map(str::to_string),
		save_sent.map(str::to_string),
		class,
		false,
		&mut Vec::new(),
	)
}

#[test]
fn a_garbled_save_sent_is_a_usage_error_with_or_without_the_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	// No account and an empty data directory: the value is still what is
	// refused, with the same code as when the account exists.
	assert_eq!(
		create_with(&config, "ghost", (None, Some("maybe")), None),
		ExitCode::from(2)
	);
	seed_account(dir.path());
	for value in ["maybe", "", "1", "yes please"] {
		assert_eq!(
			create_with(&config, "alice", (None, Some(value)), None),
			ExitCode::from(2),
			"{value:?}"
		);
	}
	assert!(
		AppPasswordStore::open(dir.path())
			.expect("open")
			.for_account("alice")
			.is_empty()
	);
}

#[test]
fn a_bad_network_binds_no_class_and_stores_nothing() {
	let dir = tempfile::tempdir().expect("tempdir");
	seed_account(dir.path());
	let config = config(dir.path());
	assert_eq!(
		create_with(
			&config,
			"alice",
			(Some("not-a-network"), None),
			Some(crate::evidence::MailClass::Marketing)
		),
		ExitCode::from(2)
	);
	assert!(
		crate::evidence::bindings::load(dir.path())
			.expect("bindings")
			.credentials
			.is_empty(),
		"a class was bound for a credential that was never made"
	);
	assert!(
		AppPasswordStore::open(dir.path())
			.expect("open")
			.for_account("alice")
			.is_empty()
	);
}
