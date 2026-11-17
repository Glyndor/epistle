use crate::config::{Config, ConfigError, Limit, SessionsWhenFull};

fn load(settings: &str) -> Result<Config, ConfigError> {
	use std::io::Write;
	let mut file = tempfile::NamedTempFile::new().expect("config file");
	writeln!(
		file,
		"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n\
		 domains = [\"example.org\", \"example.com\"]\n\
		 max_message_size = 1048576\n\
		 [[tenant]]\nname = \"acme\"\ndomains = [\"example.com\"]\n{settings}"
	)
	.expect("write config");
	Config::load(file.path())
}

fn refused(settings: &str, needle: &str) {
	let error = load(settings).expect_err("must be refused").to_string();
	assert!(
		error.contains(needle),
		"{error:?} should mention {needle:?}"
	);
}

#[test]
fn nothing_configured_is_inert() {
	let config = load("").expect("loads");
	assert!(config.limits.is_empty());
	assert!(config.limit_scopes.is_empty());
}

#[test]
fn numbers_and_unlimited_both_load() {
	let config = load(
		"[limits]\nmax_addresses_per_account = 10\nmax_api_keys_per_account = \"unlimited\"\n\
		 sessions_when_full = \"refuse\"\n\
		 [[limit_scope]]\ntenant = \"acme\"\nmax_addresses_per_account = 5\n\
		 [[limit_scope]]\ndomain = \"example.com\"\nmax_message_size = 100000\n\
		 [[limit_scope]]\naccount = \"bob\"\nmax_addresses_per_account = 0",
	)
	.expect("loads");
	assert_eq!(
		config.limits.max_addresses_per_account,
		Some(Limit::Max(10))
	);
	assert_eq!(
		config.limits.max_api_keys_per_account,
		Some(Limit::Unlimited)
	);
	assert_eq!(
		config.limits.sessions_when_full,
		Some(SessionsWhenFull::Refuse)
	);
	assert_eq!(config.limit_scopes.len(), 3);
}

#[test]
fn an_entry_names_exactly_one_target() {
	refused(
		"[[limit_scope]]\nmax_addresses_per_account = 1",
		"exactly one",
	);
	refused(
		"[[limit_scope]]\ndomain = \"example.org\"\naccount = \"bob\"",
		"exactly one",
	);
	refused("[[limit_scope]]\ntenant = \"nobody\"", "not declared");
	refused(
		"[[limit_scope]]\naccount = \"bob\"\n[[limit_scope]]\naccount = \"bob\"",
		"more than once",
	);
}

#[test]
fn a_misspelled_key_or_a_bad_value_is_refused() {
	refused(
		"[[limit_scope]]\naccount = \"bob\"\nmax_adresses_per_account = 1",
		"unknown field",
	);
	refused("[limits]\nmax_adresses = 1", "unknown field");
	refused(
		"[limits]\nmax_addresses_per_account = -1",
		"cannot be negative",
	);
	refused(
		"[limits]\nmax_addresses_per_account = \"many\"",
		"not a limit",
	);
}

#[test]
fn a_narrower_scope_may_tighten_and_may_not_loosen() {
	refused(
		"[limits]\nmax_addresses_per_account = 10\n[[limit_scope]]\ntenant = \"acme\"\nmax_addresses_per_account = 11",
		"a scope only tightens",
	);
	refused(
		"[limits]\nmax_addresses_per_account = 10\n[[limit_scope]]\naccount = \"bob\"\nmax_addresses_per_account = \"unlimited\"",
		"a scope only tightens",
	);
	refused(
		"[[limit_scope]]\ntenant = \"acme\"\nmax_api_keys_per_account = 5\n\
		 [[limit_scope]]\ndomain = \"example.com\"\nmax_api_keys_per_account = 6",
		"the tenant allows 5",
	);
	load(
		"[limits]\nmax_addresses_per_account = 10\n[[limit_scope]]\ntenant = \"acme\"\nmax_addresses_per_account = 10\n\
		 [[limit_scope]]\ndomain = \"example.com\"\nmax_addresses_per_account = 3",
	)
	.expect("equal and lower both load");
}

#[test]
fn a_scope_under_no_cap_may_set_one_and_unlimited_is_free() {
	load("[[limit_scope]]\naccount = \"bob\"\nmax_addresses_per_account = 1000000").expect("loads");
	load("[[limit_scope]]\naccount = \"bob\"\nmax_addresses_per_account = \"unlimited\"")
		.expect("loads");
}

#[test]
fn the_session_default_of_fifty_is_a_cap_a_scope_cannot_loosen() {
	refused(
		"[[limit_scope]]\naccount = \"bob\"\nmax_sessions_per_account = 51",
		"a scope only tightens",
	);
	load("[limits]\nmax_sessions_per_account = 500\n[[limit_scope]]\naccount = \"bob\"\nmax_sessions_per_account = 200")
		.expect("raised at the server first");
}

#[test]
fn message_sizes_stay_between_the_floor_and_the_server() {
	refused(
		"[[limit_scope]]\naccount = \"bob\"\nmax_message_size = 1048577",
		"a scope only tightens",
	);
	refused(
		"[[limit_scope]]\naccount = \"bob\"\nmax_message_size = 1000",
		"at least 64K octets",
	);
	refused(
		"[[limit_scope]]\naccount = \"bob\"\nmax_message_size = \"unlimited\"",
		"a scope only tightens",
	);
	refused(
		"[limits]\nmax_message_size = 100000",
		"top-level max_message_size",
	);
	load("[[limit_scope]]\naccount = \"bob\"\nmax_message_size = 65536").expect("the floor loads");
}
