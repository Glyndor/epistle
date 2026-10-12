use super::*;

fn key(domains: &[&str], account: Option<&str>) -> ApiKey {
	ApiKey {
		label: "k".into(),
		hash: "sha256:00".into(),
		expires_at: None,
		ip_cidr: None,
		scopes: vec!["read".into()],
		domains: domains.iter().map(|d| (*d).to_string()).collect(),
		account: account.map(str::to_string),
	}
}

#[test]
fn a_key_without_domains_and_without_account_is_admin() {
	assert_eq!(Principal::of_key(&key(&[], None)), Principal::Admin);
}

#[test]
fn a_key_with_domains_becomes_domains() {
	assert_eq!(
		Principal::of_key(&key(&["a.example"], None)),
		Principal::Domains(vec!["a.example".to_string()])
	);
}

#[test]
fn a_key_with_an_account_becomes_account() {
	assert_eq!(
		Principal::of_key(&key(&[], Some("alice"))),
		Principal::Account("alice".to_string())
	);
	// An `account` declaration narrows more than `domains` would have, even
	// when both are set: a key tied to one account is not a tenant key.
	assert_eq!(
		Principal::of_key(&key(&["a.example"], Some("alice"))),
		Principal::Account("alice".to_string())
	);
}

#[test]
fn an_empty_account_string_falls_back_to_domains() {
	// Defensive: a key with `account = ""` (present but empty) must not
	// collapse to an `Account("")` that admits no one; the field's intent
	// is "ties this key to one account", and an empty value is not that.
	assert_eq!(
		Principal::of_key(&key(&["a.example"], Some(""))),
		Principal::Domains(vec!["a.example".to_string()])
	);
}

#[test]
fn admin_admits_any_account() {
	let principal = Principal::Admin;
	assert!(principal.admits_account("alice", &["alice@example.org".into()]));
	assert!(principal.admits_account("ghost", &[]));
}

#[test]
fn account_admits_only_its_own_name() {
	let principal = Principal::Account("alice".to_string());
	assert!(principal.admits_account("alice", &["alice@example.org".into()]));
	assert!(!principal.admits_account("bob", &["bob@example.org".into()]));
	// A wrong name with the right addresses is still refused.
	assert!(!principal.admits_account("bob", &["alice@example.org".into()]));
}

#[test]
fn domains_admits_only_addresses_in_scope() {
	let principal = Principal::Domains(vec!["a.example".to_string()]);
	assert!(principal.admits_account("alice", &["alice@a.example".into()]));
	// Straddling accounts are out of scope, matching the existing
	// `DomainScope::admits_account` rule.
	assert!(!principal.admits_account("both", &["x@a.example".into(), "x@b.example".into()]));
}

#[test]
fn domains_rejects_account_with_no_addresses() {
	let principal = Principal::Domains(vec!["a.example".to_string()]);
	// An account with no addresses has no evidence tying it to the
	// tenant, so a tenant-scoped principal refuses it.
	assert!(!principal.admits_account("ghost", &[]));
}

#[test]
fn domains_compare_is_case_insensitive() {
	let principal = Principal::Domains(vec!["a.example".to_string()]);
	assert!(
		principal.admits_account("alice", &["alice@A.EXAMPLE".into()]),
		"DNS is case-insensitive; the principal must agree"
	);
}
