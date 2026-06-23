//! LDAP integration tests. These need a real OpenLDAP / Active Directory server
//! and only run when `INTEROP_LDAP_URL` is set; otherwise they skip so the
//! default test run needs no LDAP server.
//!
//! The orchestrator runs a live OpenLDAP container and provides the connection
//! details through environment variables. Required:
//!   INTEROP_LDAP_URL          e.g. ldap://localhost:3890
//!   INTEROP_LDAP_BIND_DN      service account DN used to search
//!   INTEROP_LDAP_BIND_PW      service account password
//!   INTEROP_LDAP_BASE_DN      base DN for the user search
//!   INTEROP_LDAP_USER         a known login (the `%s` value, e.g. a uid)
//!   INTEROP_LDAP_USER_PW      that user's correct password
//! Optional (with sensible defaults):
//!   INTEROP_LDAP_FILTER       user filter, default "(uid=%s)"
//!   INTEROP_LDAP_ACCOUNT_ATTR account attribute, default "uid"
//!   INTEROP_LDAP_MAIL_ATTR    mail attribute, default "mail"
//!   INTEROP_LDAP_EXPECT_ACCT  expected mapped account name, default = the login

use epistle::config::Ldap;
use epistle::directory_store::{LdapAuthenticator, load_ldap_accounts};

/// Build the configured [`Ldap`] from the environment, or `None` to skip.
fn ldap_config() -> Option<Ldap> {
	let url = std::env::var("INTEROP_LDAP_URL")
		.ok()
		.filter(|u| !u.is_empty())?;
	let filter = std::env::var("INTEROP_LDAP_FILTER").unwrap_or_else(|_| "(uid=%s)".to_string());
	let account_attribute =
		std::env::var("INTEROP_LDAP_ACCOUNT_ATTR").unwrap_or_else(|_| "uid".to_string());
	let mail_attribute =
		std::env::var("INTEROP_LDAP_MAIL_ATTR").unwrap_or_else(|_| "mail".to_string());
	let toml = format!(
		r#"
url = "{url}"
bind_dn = "{bind_dn}"
bind_password = "{bind_pw}"
base_dn = "{base_dn}"
user_filter = "{filter}"
account_attribute = "{account_attribute}"
mail_attribute = "{mail_attribute}"
"#,
		bind_dn = std::env::var("INTEROP_LDAP_BIND_DN").expect("INTEROP_LDAP_BIND_DN"),
		bind_pw = std::env::var("INTEROP_LDAP_BIND_PW").expect("INTEROP_LDAP_BIND_PW"),
		base_dn = std::env::var("INTEROP_LDAP_BASE_DN").expect("INTEROP_LDAP_BASE_DN"),
	);
	let config: Ldap = toml::from_str(&toml).expect("parse ldap config");
	config.validate().expect("validate ldap config");
	Some(config)
}

fn known_user() -> (String, String) {
	(
		std::env::var("INTEROP_LDAP_USER").expect("INTEROP_LDAP_USER"),
		std::env::var("INTEROP_LDAP_USER_PW").expect("INTEROP_LDAP_USER_PW"),
	)
}

#[test]
fn known_user_binds_and_resolves_to_the_expected_account() {
	let Some(config) = ldap_config() else {
		eprintln!("skipping: INTEROP_LDAP_URL not set");
		return;
	};
	let (user, password) = known_user();
	let expected = std::env::var("INTEROP_LDAP_EXPECT_ACCT").unwrap_or_else(|_| user.clone());

	let auth = LdapAuthenticator::new(config);
	assert_eq!(
		auth.authenticate(&user, &password),
		Some(expected),
		"a known user with the right password authenticates to the mapped account"
	);
}

#[test]
fn wrong_password_returns_none() {
	let Some(config) = ldap_config() else {
		eprintln!("skipping: INTEROP_LDAP_URL not set");
		return;
	};
	let (user, _) = known_user();
	let auth = LdapAuthenticator::new(config);
	assert_eq!(
		auth.authenticate(&user, "definitely-not-the-password"),
		None,
		"a wrong password fails closed"
	);
}

#[test]
fn unknown_user_returns_none() {
	let Some(config) = ldap_config() else {
		eprintln!("skipping: INTEROP_LDAP_URL not set");
		return;
	};
	let auth = LdapAuthenticator::new(config);
	assert_eq!(
		auth.authenticate("no-such-user-xyz", "whatever"),
		None,
		"an unknown user fails closed, indistinguishable from a bad password"
	);
}

#[test]
fn search_load_produces_the_known_account() {
	let Some(config) = ldap_config() else {
		eprintln!("skipping: INTEROP_LDAP_URL not set");
		return;
	};
	let (user, _) = known_user();
	let expected = std::env::var("INTEROP_LDAP_EXPECT_ACCT").unwrap_or_else(|_| user.clone());

	let accounts = load_ldap_accounts(&config).expect("load ldap accounts");
	let found = accounts
		.iter()
		.find(|account| account.name == expected)
		.expect("the known account is in the resolution load");
	assert!(
		!found.addresses.is_empty(),
		"the loaded account carries at least one address"
	);
}
