//! Unit tests for the tenant limits runtime. The end-to-end wire-up (API
//! route returns 409 on `max_accounts`, JMAP upload returns 507 on aggregate
//! `quota_bytes`, …) lives in `tenancy_tests.rs` next to the rest of the API
//! HTTP tests; this file keeps the small helpers honest in isolation.

use super::*;
use crate::config::{Account, Tenant};
use crate::directory_store::AccountStore;

fn store_with(domains: &[&str], accounts: &[(&str, &[&str])]) -> AccountStore {
	let list: Vec<Account> = accounts
		.iter()
		.map(|(name, addresses)| Account {
			name: (*name).to_string(),
			addresses: addresses.iter().map(|a| (*a).to_string()).collect(),
			password_hash: None,
			catch_all: Vec::new(),
			quota_bytes: None,
			forward: Vec::new(),
			forward_keep_local: true,
		})
		.collect();
	let dir = tempfile::tempdir().expect("tempdir");
	let domains_vec: Vec<String> = domains.iter().map(|d| (*d).to_string()).collect();
	let store = AccountStore::open(dir.path(), domains_vec, HashMap::new(), list).expect("open");
	// Hand back by leaking the tempdir so the store outlives the test.
	let _ = Box::leak(Box::new(dir));
	store
}

fn empty_limits() -> TenantLimits {
	TenantLimits::default()
}

#[test]
fn empty_config_short_circuits_to_identity() {
	let limits = empty_limits();
	assert!(limits.is_empty());
	assert!(limits.tenants().is_empty());
	assert!(limits.aggregate_send_limiters().count() == 0);
	assert!(
		limits
			.check_account_creation(&store_with(&["example.org"], &[]), &[])
			.is_ok()
	);
	assert!(
		limits
			.check_aggregate_quota(
				&store_with(&["example.org"], &[]),
				std::path::Path::new("."),
				&crate::storage::MessageCrypto::disabled(),
				&[],
				0,
			)
			.is_ok()
	);
}

#[test]
fn unknown_domain_yields_no_tenant() {
	let tenants = vec![Tenant {
		name: Some("acme".to_string()),
		domains: vec!["acme.example".to_string()],
		quota_bytes: None,
		max_accounts: Some(1),
		max_domains: None,
		submission_rate_limit_per_min: None,
	}];
	let limits = TenantLimits::from_config(&tenants);
	assert!(!limits.is_empty());
	let store = store_with(&["acme.example", "other.example"], &[]);
	assert!(
		limits
			.check_account_creation(&store, &["alice@other.example".to_string()])
			.is_ok()
	);
}

#[test]
fn max_accounts_blocks_when_cap_reached() {
	let tenants = vec![Tenant {
		name: Some("acme".to_string()),
		domains: vec!["acme.example".to_string()],
		quota_bytes: None,
		max_accounts: Some(1),
		max_domains: None,
		submission_rate_limit_per_min: None,
	}];
	let limits = TenantLimits::from_config(&tenants);
	let store = store_with(&["acme.example"], &[("alice", &["alice@acme.example"])]);
	// Already at the cap of one account; a new one in the same domain fails.
	let err = limits
		.check_account_creation(&store, &["bob@acme.example".to_string()])
		.expect_err("blocked");
	assert!(err.contains("max_accounts"), "{err}");
}

#[test]
fn max_accounts_admits_when_under_cap() {
	let tenants = vec![Tenant {
		name: Some("acme".to_string()),
		domains: vec!["acme.example".to_string()],
		quota_bytes: None,
		max_accounts: Some(2),
		max_domains: None,
		submission_rate_limit_per_min: None,
	}];
	let limits = TenantLimits::from_config(&tenants);
	let store = store_with(&["acme.example"], &[("alice", &["alice@acme.example"])]);
	limits
		.check_account_creation(&store, &["bob@acme.example".to_string()])
		.expect("under cap");
}

#[test]
fn aggregate_quota_rejects_when_over_cap() {
	let tenants = vec![Tenant {
		name: Some("acme".to_string()),
		domains: vec!["acme.example".to_string()],
		quota_bytes: Some(0),
		max_accounts: None,
		max_domains: None,
		submission_rate_limit_per_min: None,
	}];
	let limits = TenantLimits::from_config(&tenants);
	let store = store_with(&["acme.example"], &[("alice", &["alice@acme.example"])]);
	let err = limits
		.check_aggregate_quota(
			&store,
			std::path::Path::new("."),
			&crate::storage::MessageCrypto::disabled(),
			&["alice@acme.example".to_string()],
			1,
		)
		.expect_err("over zero cap");
	assert!(err.contains("aggregate storage cap"), "{err}");
}

#[test]
fn aggregate_rate_blocks_after_limit() {
	let tenants = vec![Tenant {
		name: Some("acme".to_string()),
		domains: vec!["acme.example".to_string()],
		quota_bytes: None,
		max_accounts: None,
		max_domains: None,
		submission_rate_limit_per_min: Some(1),
	}];
	let limits = TenantLimits::from_config(&tenants);
	let addresses = vec!["alice@acme.example".to_string()];
	limits
		.check_aggregate_rate(&addresses, 1_000)
		.expect("first send ok");
	let err = limits
		.check_aggregate_rate(&addresses, 1_001)
		.expect_err("second send blocked");
	assert!(err.contains("rate limit"), "{err}");
}

#[test]
fn straddling_account_counts_against_either_tenant() {
	// Two tenants, two domains. The shared account is in both, so any cap
	// is counted by either.
	let tenants = vec![
		Tenant {
			name: Some("a".to_string()),
			domains: vec!["a.example".to_string()],
			quota_bytes: None,
			max_accounts: Some(0),
			max_domains: None,
			submission_rate_limit_per_min: None,
		},
		Tenant {
			name: Some("b".to_string()),
			domains: vec!["b.example".to_string()],
			quota_bytes: None,
			max_accounts: None,
			max_domains: None,
			submission_rate_limit_per_min: None,
		},
	];
	let limits = TenantLimits::from_config(&tenants);
	let store = store_with(
		&["a.example", "b.example"],
		&[("alice", &["alice@a.example"])],
	);
	let err = limits
		.check_account_creation(
			&store,
			&[
				"shared@a.example".to_string(),
				"shared@b.example".to_string(),
			],
		)
		.expect_err("tenant a is at zero");
	assert!(err.contains("\"a\""), "{err}");
}
