//! Tests for outbound transport selection and validation.

use super::*;

fn rule(account: Option<&str>, domain: Option<&str>, kind: TransportKind) -> Transport {
	Transport {
		account: account.map(str::to_string),
		domain: domain.map(str::to_string),
		kind,
		host: None,
		port: None,
		starttls: false,
		username: None,
		password: None,
		socks_proxy: None,
	}
}

#[test]
fn account_beats_domain_beats_catch_all() {
	let rules = vec![
		rule(None, None, TransportKind::Fail), // catch-all
		rule(None, Some("example.com"), TransportKind::Relay), // domain
		rule(Some("alice"), None, TransportKind::Direct), // account
	];
	// Alice to example.com: the account rule wins.
	let chosen = select(&rules, Some("alice"), "example.com").expect("match");
	assert_eq!(chosen.kind, TransportKind::Direct);
	// Bob to example.com: the domain rule wins.
	let chosen = select(&rules, Some("bob"), "example.com").expect("match");
	assert_eq!(chosen.kind, TransportKind::Relay);
	// Bob to elsewhere: the catch-all.
	let chosen = select(&rules, Some("bob"), "other.test").expect("match");
	assert_eq!(chosen.kind, TransportKind::Fail);
}

#[test]
fn no_rules_selects_nothing() {
	assert!(select(&[], Some("alice"), "example.com").is_none());
}

#[test]
fn matching_is_case_insensitive() {
	let rules = vec![rule(None, Some("Example.COM"), TransportKind::Relay)];
	assert!(select(&rules, None, "example.com").is_some());
}

#[test]
fn relay_requires_host_and_port() {
	let mut r = rule(None, None, TransportKind::Relay);
	assert!(r.validate().is_err());
	r.host = Some("smarthost.test".into());
	r.port = Some(587);
	assert!(r.validate().is_ok());
}

#[test]
fn relay_auth_requires_starttls() {
	let mut r = rule(None, None, TransportKind::Relay);
	r.host = Some("smarthost.test".into());
	r.port = Some(587);
	r.username = Some("user".into());
	// AUTH without STARTTLS is rejected (no plaintext credentials).
	assert!(r.validate().is_err());
	r.starttls = true;
	assert!(r.validate().is_ok());
}

#[test]
fn non_relay_kinds_skip_relay_validation() {
	assert!(rule(None, None, TransportKind::Direct).validate().is_ok());
	assert!(rule(None, None, TransportKind::Fail).validate().is_ok());
}
