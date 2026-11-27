use super::*;
use crate::config::Config;

use super::test_support::{BASE, limits};

fn account(name: &str, domains: &[&str]) -> Target {
	Target::account(name, domains.iter().map(|d| d.to_string()).collect())
}

fn value(limits: &Limits, kind: Kind, target: &Target) -> Option<u64> {
	limits.resolve(kind, target).map(|cap| cap.value)
}

#[test]
fn nothing_configured_caps_nothing_but_the_old_sessions_cap_and_the_message() {
	let limits = limits("");
	assert!(limits.is_inert());
	let bob = account("bob", &["example.org"]);
	for kind in Kind::ALL {
		let expected = match kind {
			Kind::MessageSize => Some(10_485_760),
			Kind::Sessions => Some(50),
			_ => None,
		};
		assert_eq!(value(&limits, kind, &bob), expected, "{kind:?}");
	}
}

#[test]
fn each_scope_sets_its_own_cap() {
	let limits = limits(
		"[limits]\nmax_addresses_per_account = 100\n\
		 [[limit_scope]]\ntenant = \"acme\"\nmax_addresses_per_account = 50\n\
		 [[limit_scope]]\ndomain = \"example.org\"\nmax_addresses_per_account = 20\n\
		 [[limit_scope]]\naccount = \"bob\"\nmax_addresses_per_account = 3",
	);
	let pick = |target: &Target| limits.resolve(Kind::Addresses, target).expect("a cap");
	assert_eq!(pick(&account("eve", &["example.net"])).value, 100);
	assert_eq!(pick(&account("eve", &["example.net"])).set_by, "the server");
	assert_eq!(pick(&account("eve", &["example.com"])).value, 50);
	assert_eq!(
		pick(&account("eve", &["example.com"])).set_by,
		"tenant acme"
	);
	assert_eq!(pick(&account("eve", &["example.org"])).value, 20);
	assert_eq!(
		pick(&account("eve", &["example.org"])).set_by,
		"domain example.org"
	);
	assert_eq!(pick(&account("bob", &["example.org"])).value, 3);
	assert_eq!(
		pick(&account("Bob", &["example.com"])).set_by,
		"account Bob"
	);
}

#[test]
fn a_narrower_scope_tightens_and_never_loosens_even_past_the_load() {
	// The load refuses these entries; the resolution must hold if one got in.
	let mut config = {
		use std::io::Write;
		let mut file = tempfile::NamedTempFile::new().expect("config file");
		writeln!(
			file,
			"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n{BASE}\n\
			 [limits]\nmax_addresses_per_account = 10"
		)
		.expect("write config");
		Config::load(file.path()).expect("loads")
	};
	config.limit_scopes.push(crate::config::LimitScope {
		account: Some("bob".into()),
		caps: Caps {
			max_addresses_per_account: Some(Limit::Max(99)),
			..Caps::default()
		},
		..Default::default()
	});
	config.limit_scopes.push(crate::config::LimitScope {
		account: Some("eve".into()),
		caps: Caps {
			max_addresses_per_account: Some(Limit::Unlimited),
			..Caps::default()
		},
		..Default::default()
	});
	let limits = Limits::from_config(&config);
	for name in ["bob", "eve"] {
		assert_eq!(
			value(&limits, Kind::Addresses, &account(name, &["example.org"])),
			Some(10),
			"{name}"
		);
	}
}

#[test]
fn unlimited_at_the_server_means_no_cap_and_a_scope_can_still_cap() {
	let limits = limits(
		"[limits]\nmax_sessions_per_account = \"unlimited\"\n\
		 [[limit_scope]]\naccount = \"bob\"\nmax_sessions_per_account = 2",
	);
	assert_eq!(
		value(&limits, Kind::Sessions, &account("eve", &["example.org"])),
		None
	);
	assert_eq!(
		value(&limits, Kind::Sessions, &account("bob", &["example.org"])),
		Some(2)
	);
}

#[test]
fn an_account_in_several_domains_gets_the_strictest() {
	let limits = limits(
		"[[limit_scope]]\ndomain = \"example.org\"\nmax_api_keys_per_account = 9\n\
		 [[limit_scope]]\ndomain = \"example.net\"\nmax_api_keys_per_account = 4",
	);
	assert_eq!(
		value(
			&limits,
			Kind::ApiKeys,
			&account("bob", &["example.org", "example.net", "example.com"])
		),
		Some(4)
	);
}

#[test]
fn a_domain_alias_takes_the_cap_of_the_domain_it_delivers_to() {
	use std::io::Write;
	let mut file = tempfile::NamedTempFile::new().expect("config file");
	writeln!(
		file,
		"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n{BASE}\n\
		 [domain_aliases]\n\"alias.example.net\" = \"example.org\"\n\
		 [[limit_scope]]\ndomain = \"example.org\"\nmax_aliases_per_domain = 7"
	)
	.expect("write config");
	let limits = Limits::from_config(&Config::load(file.path()).expect("loads"));
	assert_eq!(
		value(&limits, Kind::Aliases, &Target::domain("alias.example.net")),
		Some(7)
	);
}

#[test]
fn the_message_size_is_the_server_value_until_a_scope_lowers_it() {
	let limits = limits(
		"[[limit_scope]]\ndomain = \"example.org\"\nmax_message_size = 100000\n\
		 [[limit_scope]]\naccount = \"bob\"\nmax_message_size = 70000",
	);
	assert_eq!(
		value(
			&limits,
			Kind::MessageSize,
			&account("eve", &["example.net"])
		),
		Some(10_485_760)
	);
	assert_eq!(
		value(
			&limits,
			Kind::MessageSize,
			&account("eve", &["example.org"])
		),
		Some(100_000)
	);
	let bob = account("bob", &["example.org"]);
	assert!(limits.admit_message(&bob, 70_000, "account bob").is_ok());
	let refusal = limits
		.admit_message(&bob, 70_001, "account bob")
		.expect_err("over");
	let text = refusal.to_string();
	assert!(
		text.contains("70001 bytes") && text.contains("70000 bytes"),
		"{text}"
	);
	assert!(
		text.contains("account bob") && text.contains("max_message_size"),
		"{text}"
	);
}

#[test]
fn admit_refuses_at_the_cap_and_says_which_limit_and_how_to_make_room() {
	let limits = limits("[[limit_scope]]\naccount = \"bob\"\nmax_app_passwords_per_account = 2");
	let bob = account("bob", &["example.org"]);
	assert!(
		limits
			.admit(Kind::AppPasswords, &bob, 1, "account bob")
			.is_ok()
	);
	let refusal = limits
		.admit(Kind::AppPasswords, &bob, 2, "account bob")
		.expect_err("at the cap");
	let text = refusal.to_string();
	for part in [
		"account bob",
		"2 app passwords per account",
		"set by account bob",
		"remove an app password",
		"max_app_passwords_per_account",
	] {
		assert!(text.contains(part), "{text:?} lacks {part:?}");
	}
}

#[test]
fn a_cap_of_zero_allows_none() {
	let limits = limits("[[limit_scope]]\naccount = \"bob\"\nmax_addresses_per_account = 0");
	assert!(
		limits
			.admit(Kind::Addresses, &account("bob", &[]), 0, "account bob")
			.is_err()
	);
}

/// A tenant caps the accounts it holds: the second account is refused and
/// the refusal names the tenant and its cap. A tenant without a cap refuses
/// nothing, and an account that stays in its own tenant keeps its place.
#[test]
fn a_tenant_caps_the_accounts_it_holds() {
	let tenant = |name: &str, domain: &str, cap| crate::config::Tenant {
		name: Some(name.to_string()),
		domains: vec![domain.to_string()],
		quota_bytes: None,
		max_accounts: cap,
		max_domains: None,
		submission_rate_limit_per_min: None,
		encryption_key_file: None,
		webhook: None,
	};
	let caps = TenantAccountCaps::from_tenants(&[
		tenant("acme", "example.com", Some(1)),
		tenant("open", "example.net", None),
	]);
	assert!(!caps.is_empty());
	let held: Vec<Vec<String>> = vec![vec!["alice@example.com".to_string()]];
	let refusal = caps
		.refuse_creation(
			&["bob@example.com".to_string()],
			held.iter().map(|addresses| addresses.as_slice()),
		)
		.expect("the tenant holds one account already");
	assert!(refusal.contains("tenant \"acme\""), "{refusal}");
	assert!(refusal.contains("max_accounts cap of 1"), "{refusal}");
	assert!(
		caps.refuse_creation(
			&["eve@example.net".to_string()],
			held.iter().map(|addresses| addresses.as_slice()),
		)
		.is_none(),
		"a tenant without a cap refuses nothing"
	);
	assert!(
		caps.refuse_move(
			&["alice@example.com".to_string()],
			&[
				"alice@example.com".to_string(),
				"alice2@example.com".to_string()
			],
			held.iter().map(|addresses| addresses.as_slice()),
		)
		.is_none(),
		"an account that stays in its own tenant keeps its place"
	);
	assert!(
		caps.refuse_move(
			&["zed@example.net".to_string()],
			&["zed@example.com".to_string()],
			held.iter().map(|addresses| addresses.as_slice()),
		)
		.is_some(),
		"an account that moves into a full tenant takes a place there"
	);
}

#[test]
fn the_session_policy_is_the_most_specific_that_says() {
	let limits = limits(
		"[limits]\nsessions_when_full = \"refuse\"\n\
		 [[limit_scope]]\naccount = \"bob\"\nsessions_when_full = \"end_oldest\"",
	);
	assert_eq!(
		limits.sessions_when_full(&account("eve", &["example.org"])),
		SessionsWhenFull::Refuse
	);
	assert_eq!(
		limits.sessions_when_full(&account("bob", &["example.org"])),
		SessionsWhenFull::EndOldest
	);
	assert_eq!(
		super::Limits::default().sessions_when_full(&Target::default()),
		SessionsWhenFull::EndOldest
	);
}

#[derive(Clone, Default)]
struct Sink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Sink {
	fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
		self.0.lock().unwrap().extend_from_slice(bytes);
		Ok(bytes.len())
	}
	fn flush(&mut self) -> std::io::Result<()> {
		Ok(())
	}
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Sink {
	type Writer = Sink;
	fn make_writer(&'a self) -> Sink {
		self.clone()
	}
}

#[test]
fn the_log_line_names_no_account_domain_or_tenant() {
	let limits = limits(
		"[[limit_scope]]\ntenant = \"acme\"\nmax_addresses_per_account = 1\n\
		 [[limit_scope]]\naccount = \"alice.secret\"\nmax_addresses_per_account = 1",
	);
	for target in [
		account("alice.secret", &["example.org"]),
		account("bob", &["example.com"]),
	] {
		let refusal = limits
			.admit(Kind::Addresses, &target, 1, "account whoever")
			.expect_err("full");
		let sink = Sink::default();
		let subscriber = tracing_subscriber::fmt()
			.with_writer(sink.clone())
			.with_ansi(false)
			.finish();
		tracing::subscriber::with_default(subscriber, || {
			refusal.log(target.account.as_deref().unwrap());
		});
		let line = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
		assert!(
			line.contains("limit reached") && line.contains("cap=1"),
			"{line}"
		);
		for name in ["alice", "secret", "acme", "example", "bob", "whoever"] {
			assert!(
				!line.contains(name),
				"the log line carries an account or domain name"
			);
		}
		// The text for the person refused still says everything.
		assert!(refusal.to_string().contains("account whoever"));
	}
}
