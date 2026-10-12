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
	assert_eq!(
		Principal::kind_of_key(&key(&[], None)),
		PrincipalKind::Admin
	);
}

#[test]
fn a_key_with_domains_becomes_domains() {
	assert_eq!(
		Principal::kind_of_key(&key(&["a.example"], None)),
		PrincipalKind::Domains(vec!["a.example".to_string()])
	);
}

#[test]
fn a_key_with_an_account_becomes_account() {
	assert_eq!(
		Principal::kind_of_key(&key(&[], Some("alice"))),
		PrincipalKind::Account("alice".to_string())
	);
	// An `account` declaration narrows more than `domains` would have, even
	// when both are set: a key tied to one account is not a tenant key.
	assert_eq!(
		Principal::kind_of_key(&key(&["a.example"], Some("alice"))),
		PrincipalKind::Account("alice".to_string())
	);
}

#[test]
fn an_empty_account_string_admits_no_account() {
	// A key with `account = ""` (present but empty) names no account. It
	// must not be read as "no binding" and widen to the domains, or to
	// every account when `domains` is empty too.
	for domains in [&[][..], &["a.example"][..]] {
		let principal = Principal::kind_of_key(&key(domains, Some(""))).into_principal(None);
		assert!(
			!principal.admits_account("ann", &["ann@a.example".into()]),
			"account = \"\" with domains {domains:?} must reach no account"
		);
	}
}

#[test]
fn a_token_that_matches_no_credential_reaches_no_account() {
	// The middleware matched the bearer, but by the time the handler
	// resolves the principal the key set no longer holds it (a reload
	// removed the key in between). The request must reach nothing, not
	// fall back to the reach of the configured token.
	let dir = tempfile::tempdir().expect("tempdir");
	let state = crate::api::tests::test_state(dir.path(), 0);
	let auth = MatchedAuth {
		token: Some("removed-key-secret".to_string()),
		client_ip: None,
		configured: false,
	};
	let principal = Principal::for_token(&state, &auth);
	assert!(
		!principal.admits_account("alice", &["alice@example.org".into()]),
		"a credential that matches no key must reach no account"
	);
	assert!(
		state
			.require_scope_for_principal(&principal, crate::api::api_keys::Scope::Write)
			.is_err(),
		"a credential that matches no key must hold no scope"
	);
}

#[test]
fn admin_admits_any_account() {
	let principal = Principal::Admin { credential: None };
	assert!(principal.admits_account("alice", &["alice@example.org".into()]));
	assert!(principal.admits_account("ghost", &[]));
}

#[test]
fn account_admits_only_its_own_name() {
	let principal = Principal::Account {
		name: "alice".to_string(),
		credential: None,
	};
	assert!(principal.admits_account("alice", &["alice@example.org".into()]));
	assert!(!principal.admits_account("bob", &["bob@example.org".into()]));
	// A wrong name with the right addresses is still refused.
	assert!(!principal.admits_account("bob", &["alice@example.org".into()]));
}

#[test]
fn domains_admits_only_addresses_in_scope() {
	let principal = Principal::Domains {
		domains: vec!["a.example".to_string()],
		credential: None,
	};
	assert!(principal.admits_account("alice", &["alice@a.example".into()]));
	// Straddling accounts are out of scope, matching the existing
	// `DomainScope::admits_account` rule.
	assert!(!principal.admits_account("both", &["x@a.example".into(), "x@b.example".into()]));
}

#[test]
fn domains_rejects_account_with_no_addresses() {
	let principal = Principal::Domains {
		domains: vec!["a.example".to_string()],
		credential: None,
	};
	// An account with no addresses has no evidence tying it to the
	// tenant, so a tenant-scoped principal refuses it.
	assert!(!principal.admits_account("ghost", &[]));
}

#[test]
fn domains_compare_is_case_insensitive() {
	let principal = Principal::Domains {
		domains: vec!["a.example".to_string()],
		credential: None,
	};
	assert!(
		principal.admits_account("alice", &["alice@A.EXAMPLE".into()]),
		"DNS is case-insensitive; the principal must agree"
	);
}

#[test]
fn admissible_accounts_filters_using_the_same_rule() {
	let accounts = vec![
		AccountView {
			name: "ann".to_string(),
			addresses: vec!["ann@a.example".to_string()],
			dynamic: false,
		},
		AccountView {
			name: "bob".to_string(),
			addresses: vec!["bob@b.example".to_string()],
			dynamic: false,
		},
		AccountView {
			name: "both".to_string(),
			addresses: vec!["both@a.example".to_string(), "both@b.example".to_string()],
			dynamic: false,
		},
	];
	let principal = Principal::Domains {
		domains: vec!["a.example".to_string()],
		credential: None,
	};
	let names: Vec<&str> = principal
		.admissible_accounts(&accounts)
		.iter()
		.map(|a| a.name.as_str())
		.collect();
	assert_eq!(names, vec!["ann"], "{names:?}");
}
