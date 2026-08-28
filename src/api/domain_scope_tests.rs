use super::*;

fn key(domains: &[&str]) -> ApiKey {
	ApiKey {
		label: "k".into(),
		hash: "sha256:00".into(),
		expires_at: None,
		ip_cidr: None,
		scopes: vec!["read".into()],
		domains: domains.iter().map(|d| (*d).to_string()).collect(),
	}
}

#[test]
fn a_key_without_domains_keeps_the_reach_it_always_had() {
	assert_eq!(DomainScope::of_key(&key(&[])), DomainScope::All);
	assert!(DomainScope::All.admits_domain("anything.example"));
	assert!(DomainScope::All.admits_account(["a@anywhere.example"].into_iter()));
}

#[test]
fn a_scoped_key_admits_only_its_own_domains() {
	let scope = DomainScope::of_key(&key(&["A.example"]));
	assert!(scope.admits_domain("a.example"));
	assert!(scope.admits_domain("A.EXAMPLE"));
	assert!(!scope.admits_domain("b.example"));
}

#[test]
fn an_account_straddling_two_domains_is_out_of_scope() {
	let scope = DomainScope::of_key(&key(&["a.example"]));
	assert!(scope.admits_account(["x@a.example"].into_iter()));
	// One address inside the scope must not vouch for the one outside it:
	// deleting this account would reach b.example, which the key never got.
	assert!(!scope.admits_account(["x@a.example", "x@b.example"].into_iter()));
}

#[test]
fn an_account_with_no_addresses_is_out_of_scope_for_a_scoped_key() {
	let scope = DomainScope::of_key(&key(&["a.example"]));
	// Nothing places it in a tenant, so there is no evidence it belongs to
	// this one. Fail closed.
	assert!(!scope.admits_account(std::iter::empty()));
	assert!(DomainScope::All.admits_account(std::iter::empty()));
}

#[test]
fn a_malformed_address_never_admits() {
	let scope = DomainScope::of_key(&key(&["a.example"]));
	assert!(!scope.admits_account(["not-an-address"].into_iter()));
}
