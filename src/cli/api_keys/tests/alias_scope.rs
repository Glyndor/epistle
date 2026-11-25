//! The `alias` scope: a key may hold it, a typo is refused, and a key bound
//! to one account may not, since the alias routes are administrative.

use super::*;
use crate::api::ApiKeyStore;

fn config(data_dir: &std::path::Path) -> Config {
	let toml = format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\n\
		 domains = [\"example.org\"]\n\
		 [[accounts]]\nname = \"alice\"\naddresses = [\"alice@example.org\"]\n",
		data_dir.display()
	);
	toml::from_str(&toml).expect("config parses")
}

fn make(config: &Config, label: &str, scope: &str, account: Option<&str>) -> ExitCode {
	create(
		config,
		NewKey {
			label: label.to_string(),
			scopes: vec![scope.to_string()],
			domains: vec!["example.org".to_string()],
			account: account.map(str::to_string),
			..NewKey::default()
		},
		false,
		&mut Vec::new(),
		&mut Vec::new(),
	)
}

#[test]
fn a_key_holds_the_alias_scope_and_a_typo_of_it_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	assert_eq!(make(&config, "aliases", "alias", None), ExitCode::SUCCESS);
	let keys = ApiKeyStore::open(dir.path()).expect("open");
	assert_eq!(keys.keys()[0].scopes, ["alias"]);
	assert!(parse_scope("alias").is_ok());
	let error = parse_scope("aliases").expect_err("not a scope");
	assert!(error.contains("scim, alias or ban"), "{error}");
}

#[test]
fn a_key_bound_to_an_account_cannot_hold_it() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	for scope in ["alias", "scim"] {
		assert_eq!(
			make(&config, "bound", scope, Some("alice")),
			ExitCode::from(crate::cli::exit::POLICY),
			"{scope}"
		);
	}
	assert!(
		ApiKeyStore::open(dir.path())
			.expect("open")
			.keys()
			.is_empty()
	);
}
