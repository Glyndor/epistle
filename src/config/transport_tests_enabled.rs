//! A relay rule switched off is never selected.

use super::*;

fn rule(account: Option<&str>, domain: Option<&str>, kind: TransportKind) -> Transport {
	Transport {
		account: account.map(str::to_string),
		domain: domain.map(str::to_string),
		kind,
		host: Some("smarthost.test".into()),
		port: Some(587),
		starttls: false,
		username: None,
		password: None,
		socks_proxy: None,
		enabled: true,
	}
}

fn off(mut rule: Transport) -> Transport {
	rule.enabled = false;
	rule
}

#[test]
fn a_disabled_rule_is_skipped_for_the_next_one() {
	let rules = vec![
		rule(None, None, TransportKind::Fail),
		off(rule(None, Some("example.com"), TransportKind::Relay)),
	];
	let chosen = select(&rules, Some("bob"), "example.com").expect("the catch-all applies");
	assert_eq!(chosen.kind, TransportKind::Fail);
}

#[test]
fn a_disabled_rule_alone_leaves_the_built_in_direct_default() {
	let rules = vec![off(rule(None, None, TransportKind::Relay))];
	assert!(select(&rules, Some("bob"), "example.com").is_none());
}

#[test]
fn rules_are_on_by_default() {
	let parsed: Transport =
		toml::from_str("kind = \"relay\"\nhost = \"h\"\nport = 25").expect("parse");
	assert!(parsed.enabled);
	let parsed: Transport =
		toml::from_str("kind = \"relay\"\nhost = \"h\"\nport = 25\nenabled = false")
			.expect("parse");
	assert!(!parsed.enabled);
}

#[test]
fn only_a_relay_rule_may_be_switched_off() {
	assert!(
		off(rule(None, None, TransportKind::Relay))
			.validate()
			.is_ok()
	);
	for kind in [TransportKind::Fail, TransportKind::Direct] {
		assert_eq!(
			off(rule(None, None, kind)).validate().unwrap_err(),
			"only a relay transport can be switched off with enabled = false; \
			 remove a fail or direct rule instead"
		);
	}
}

#[test]
fn a_switched_off_relay_does_not_count_as_a_warm_up_relay() {
	let rules = vec![
		rule(None, Some("a.example"), TransportKind::Relay),
		off(rule(None, Some("b.example"), TransportKind::Relay)),
	];
	assert_eq!(
		crate::queue::warmup::relay_hosts(&rules),
		vec!["smarthost.test".to_string()]
	);
	assert!(crate::queue::warmup::relay_hosts(&rules[1..]).is_empty());
}

#[test]
fn the_loader_refuses_a_fail_rule_that_is_switched_off() {
	let config: crate::config::Config = toml::from_str(
		"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n\
		 [[transport]]\nkind = \"fail\"\nenabled = false\n",
	)
	.expect("parse");
	assert!(
		config
			.validate()
			.unwrap_err()
			.to_string()
			.contains("only a relay transport can be switched off"),
	);
}
