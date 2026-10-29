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

fn view(name: &str, addresses: &[&str]) -> AccountView {
	AccountView {
		name: name.to_string(),
		addresses: addresses.iter().map(|a| (*a).to_string()).collect(),
		dynamic: false,
		display_name: None,
	}
}

#[test]
fn a_key_without_domains_and_without_account_reaches_everything() {
	let principal = Principal::of_key(&key(&[], None), None);
	assert!(principal.admits_account("alice", &["alice@example.org".into()]));
	assert!(principal.admits_domain("anything.example"));
	assert!(principal.is_unrestricted());
}

#[test]
fn a_key_with_domains_is_confined_to_them() {
	let principal = Principal::of_key(&key(&["a.example"], None), None);
	assert!(principal.admits_account("alice", &["alice@a.example".into()]));
	assert!(!principal.admits_account("bob", &["bob@b.example".into()]));
	assert!(principal.admits_domain("a.example"));
	assert!(!principal.admits_domain("b.example"));
	assert!(!principal.is_unrestricted());
}

#[test]
fn a_key_with_an_account_is_bound_to_it() {
	let principal = Principal::of_key(&key(&[], Some("alice")), None);
	assert!(principal.admits_account("alice", &["alice@example.org".into()]));
	assert!(!principal.admits_account("bob", &["bob@example.org".into()]));
	// A wrong name with the right addresses is still refused.
	assert!(!principal.admits_account("bob", &["alice@example.org".into()]));
	assert!(!principal.is_unrestricted());
}

#[test]
fn a_key_with_an_account_and_domains_is_confined_by_both() {
	// Both declarations narrow the reach, and they narrow it at the same
	// time: the account binding picks the account, the domain binding
	// decides whether that account is inside the declared domains.
	let principal = Principal::of_key(&key(&["a.example"], Some("alice")), None);
	assert!(principal.admits_account("alice", &["alice@a.example".into()]));
	// The account is the bound one, but it lives outside the domains.
	assert!(
		!principal.admits_account("alice", &["alice@b.example".into()]),
		"the domain binding must still apply to the bound account"
	);
	// Inside the domains, but not the bound account.
	assert!(
		!principal.admits_account("bob", &["bob@a.example".into()]),
		"the account binding must still apply inside the domains"
	);
}

#[test]
fn an_empty_account_string_admits_no_account() {
	// A key with `account = ""` (present but empty) names no account. It
	// must not be read as "no binding" and widen to the domains, or to
	// every account when `domains` is empty too.
	for domains in [&[][..], &["a.example"][..]] {
		let principal = Principal::of_key(&key(domains, Some("")), None);
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
	let state = crate::api::tests::base::test_state(dir.path(), 0);
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
			.require_scope_for_principal(&principal, Scope::Write)
			.is_err(),
		"a credential that matches no key must hold no scope"
	);
}

#[test]
fn the_unrestricted_reach_admits_any_account() {
	let principal = Principal::unrestricted();
	assert!(principal.admits_account("alice", &["alice@example.org".into()]));
	assert!(principal.admits_account("ghost", &[]));
}

#[test]
fn domains_admit_only_addresses_in_scope() {
	let principal = Principal::of_key(&key(&["a.example"], None), None);
	// Straddling accounts are out of scope: one address inside the scope
	// must not vouch for the one outside it.
	assert!(!principal.admits_account("both", &["x@a.example".into(), "x@b.example".into()]));
}

#[test]
fn domains_reject_account_with_no_addresses() {
	let principal = Principal::of_key(&key(&["a.example"], None), None);
	// An account with no addresses has no evidence tying it to the
	// tenant, so a tenant-scoped principal refuses it.
	assert!(!principal.admits_account("ghost", &[]));
}

#[test]
fn a_malformed_address_never_admits() {
	let principal = Principal::of_key(&key(&["a.example"], None), None);
	assert!(!principal.admits_addresses(&["not-an-address".to_string()]));
}

#[test]
fn domains_compare_is_case_insensitive() {
	let principal = Principal::of_key(&key(&["a.example"], None), None);
	assert!(
		principal.admits_account("alice", &["alice@A.EXAMPLE".into()]),
		"DNS is case-insensitive; the principal must agree"
	);
}

#[test]
fn admissible_accounts_filters_using_the_same_rule() {
	let accounts = vec![
		view("ann", &["ann@a.example"]),
		view("bob", &["bob@b.example"]),
		view("both", &["both@a.example", "both@b.example"]),
	];
	let principal = Principal::of_key(&key(&["a.example"], None), None);
	let names: Vec<&str> = principal
		.admissible_accounts(&accounts)
		.iter()
		.map(|a| a.name.as_str())
		.collect();
	assert_eq!(names, vec!["ann"], "{names:?}");
}

#[test]
fn a_key_holds_only_the_scopes_it_declares() {
	let mut key = key(&[], None);
	key.scopes = vec!["read".to_string()];
	let principal = Principal::of_key(&key, None);
	assert!(principal.admits_scope(Scope::Read));
	assert!(!principal.admits_scope(Scope::Write));
	assert!(!principal.admits_scope(Scope::Send));
}

#[test]
fn a_legacy_key_without_scopes_holds_every_scope() {
	let mut key = key(&[], None);
	key.scopes = Vec::new();
	let principal = Principal::of_key(&key, None);
	assert!(principal.admits_scope(Scope::Read));
	assert!(principal.admits_scope(Scope::Write));
	assert!(principal.admits_scope(Scope::Send));
	assert!(principal.admits_scope(Scope::Scim));
}

#[test]
fn a_key_with_an_unreadable_scope_holds_none() {
	let mut key = key(&[], None);
	key.scopes = vec!["teleport".to_string()];
	let principal = Principal::of_key(&key, None);
	assert!(
		!principal.admits_scope(Scope::Read),
		"a scope this build cannot read is a scope the key does not hold"
	);
}

#[test]
fn a_scoped_key_holds_no_shared_state() {
	let principal = Principal::of_key(&key(&["a.example"], None), None);
	assert!(!principal.is_unrestricted());
}

#[test]
fn an_account_bound_key_holds_no_shared_state() {
	let principal = Principal::of_key(&key(&[], Some("alice")), None);
	assert!(!principal.is_unrestricted());
}
