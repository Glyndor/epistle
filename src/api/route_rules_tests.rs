//! Every HTTP route declares its rule: the scope a key needs and what it does
//! about the domains the key is confined to. The table below is the review
//! checklist for a new route; the first test fails when the routers and the
//! table disagree, so a route cannot be added without deciding its domain rule,
//! and the second fails when a row names a test that does not exist.

use std::collections::BTreeSet;

/// What a route does about a key confined to some domains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Domain {
	/// No tenant data at all: liveness, discovery documents, a constant answer.
	Open,
	/// Acts for the principal the bearer carries and never for one the request
	/// names (JMAP, send, deliveries).
	Principal,
	/// The result is limited to the accounts and domains the key covers.
	Filtered,
	/// The `{name}` account of the path must be covered, or the answer is the
	/// same `404` as for an account that does not exist.
	AccountParam,
	/// Data shared by every tenant: refused to a confined key.
	Unconfined,
	/// The caller proves an account with its own credentials; no key is used.
	Credentials,
}

struct Rule {
	/// The full path pattern as the router registers it.
	pattern: &'static str,
	/// The key scope the route needs: `read`, `write`, `send`, `scim` or `none`.
	scope: &'static str,
	domain: Domain,
	/// The test that proves the rule. `-` only for `Open` routes.
	covered_by: &'static str,
}

const fn rule(
	pattern: &'static str,
	scope: &'static str,
	domain: Domain,
	covered_by: &'static str,
) -> Rule {
	Rule {
		pattern,
		scope,
		domain,
		covered_by,
	}
}

const RULES: &[Rule] = &[
	rule("/healthz", "none", Domain::Open, "-"),
	// The description of the API itself: no tenant data.
	rule("/api/v1/openapi.json", "read", Domain::Open, "-"),
	// JMAP and send act for the principal behind the key.
	rule(
		"/.well-known/jmap",
		"read",
		Domain::Principal,
		"scoped_key_session_lists_only_admissible_accounts",
	),
	rule(
		"/jmap/session",
		"read",
		Domain::Principal,
		"scoped_key_session_lists_only_admissible_accounts",
	),
	rule(
		"/jmap/api",
		"read/write/send",
		Domain::Principal,
		"scoped_key_cannot_get_email_of_foreign_account",
	),
	rule(
		"/jmap/ws",
		"read",
		Domain::Principal,
		"the_websocket_refuses_the_other_tenants_account",
	),
	rule(
		"/jmap/eventsource",
		"read",
		Domain::Principal,
		"the_event_source_pushes_the_own_account_only",
	),
	rule(
		"/jmap/download/{account_id}/{blob_id}/{name}",
		"read",
		Domain::Principal,
		"the_download_route_refuses_the_other_tenants_account",
	),
	rule(
		"/jmap/upload/{account_id}",
		"write",
		Domain::Principal,
		"the_upload_route_takes_the_own_account_only",
	),
	rule(
		"/api/v1/send",
		"send",
		Domain::Principal,
		"confined_key_cannot_send_from_a_foreign_or_unowned_address",
	),
	rule(
		"/api/v1/deliveries",
		"read",
		Domain::Principal,
		"an_account_bound_key_only_sees_its_own_records",
	),
	// Management API.
	rule(
		"/api/v1/status",
		"read",
		Domain::Filtered,
		"the_status_counters_cover_only_the_tenants_own_scope",
	),
	rule(
		"/api/v1/auth/verify",
		"write",
		Domain::Filtered,
		"credential_verification_does_not_confirm_another_tenants_password",
	),
	rule(
		"/api/v1/domains",
		"read",
		Domain::Filtered,
		"a_scoped_key_lists_only_its_own_domains",
	),
	rule(
		"/api/v1/accounts",
		"read/write",
		Domain::Filtered,
		"a_scoped_key_lists_only_its_own_accounts",
	),
	rule(
		"/api/v1/accounts/{name}",
		"write",
		Domain::AccountParam,
		"a_scoped_key_cannot_delete_another_tenants_account",
	),
	rule(
		"/api/v1/accounts/{name}/password",
		"write",
		Domain::AccountParam,
		"a_scoped_key_cannot_reset_another_tenants_password",
	),
	rule(
		"/api/v1/accounts/{name}/display_name",
		"write",
		Domain::AccountParam,
		"two_factor_and_display_name_of_another_tenants_account_are_out_of_reach",
	),
	rule(
		"/api/v1/accounts/{name}/totp",
		"write",
		Domain::AccountParam,
		"two_factor_and_display_name_of_another_tenants_account_are_out_of_reach",
	),
	rule(
		"/api/v1/accounts/{name}/mailboxes",
		"read",
		Domain::AccountParam,
		"a_scoped_key_cannot_list_another_tenants_mailboxes",
	),
	rule(
		"/api/v1/accounts/{name}/masked",
		"read/write",
		Domain::AccountParam,
		"masked_addresses_of_another_tenants_account_are_out_of_reach",
	),
	rule(
		"/api/v1/accounts/{name}/masked/{address}",
		"write",
		Domain::AccountParam,
		"masked_addresses_of_another_tenants_account_are_out_of_reach",
	),
	rule(
		"/api/v1/accounts/{name}/archive",
		"read",
		Domain::AccountParam,
		"the_archive_of_another_tenants_account_is_out_of_reach",
	),
	rule(
		"/api/v1/accounts/{name}/archive/{id}/restore",
		"write",
		Domain::AccountParam,
		"the_archive_of_another_tenants_account_is_out_of_reach",
	),
	rule(
		"/api/v1/queue",
		"read",
		Domain::Filtered,
		"the_queue_lists_only_the_tenants_own_messages",
	),
	rule(
		"/api/v1/queue/{id}",
		"write",
		Domain::Filtered,
		"another_tenants_queue_entry_cannot_be_removed",
	),
	rule(
		"/api/v1/suppression",
		"read",
		Domain::Unconfined,
		"the_shared_suppression_list_is_not_for_a_confined_key",
	),
	rule(
		"/api/v1/suppression/{address}",
		"write",
		Domain::Unconfined,
		"the_shared_suppression_list_is_not_for_a_confined_key",
	),
	// SCIM.
	rule("/scim/v2/ServiceProviderConfig", "scim", Domain::Open, "-"),
	rule("/scim/v2/Schemas", "scim", Domain::Open, "-"),
	rule("/scim/v2/ResourceTypes", "scim", Domain::Open, "-"),
	rule(
		"/scim/v2/Users",
		"scim",
		Domain::Filtered,
		"the_list_holds_only_the_tenants_own_accounts",
	),
	rule(
		"/scim/v2/Users/{id}",
		"scim",
		Domain::AccountParam,
		"another_tenants_account_is_not_found_by_id",
	),
	rule("/scim/v2/Groups", "scim", Domain::Open, "-"),
	rule("/scim/v2/Groups/{id}", "scim", Domain::Open, "-"),
	// OAuth: the codes and the account credentials are the proof.
	rule(
		"/oauth/token",
		"none",
		Domain::Credentials,
		"device_flow_pending_then_approved_issues_verifiable_token",
	),
	rule(
		"/oauth/device_authorization",
		"none",
		Domain::Credentials,
		"device_flow_pending_then_approved_issues_verifiable_token",
	),
	rule(
		"/oauth/device/approve",
		"none",
		Domain::Credentials,
		"device_approve_rejects_bad_credentials_and_unknown_code",
	),
	rule(
		"/oauth/authorize",
		"none",
		Domain::Credentials,
		"pkce_authorize_rejects_bad_credentials",
	),
];

/// Every `.route("<path>"` in `source`, with `prefix` put in front.
fn routes_in(source: &str, prefix: &str) -> BTreeSet<String> {
	let mut found = BTreeSet::new();
	let mut rest = source;
	while let Some(at) = rest.find(".route(") {
		rest = &rest[at + ".route(".len()..];
		let trimmed = rest.trim_start();
		if let Some(quoted) = trimmed.strip_prefix('"')
			&& let Some(end) = quoted.find('"')
		{
			found.insert(format!("{prefix}{}", &quoted[..end]));
		}
	}
	found
}

fn registered_routes() -> BTreeSet<String> {
	let mut all = BTreeSet::new();
	for (source, prefix) in [
		(include_str!("mod.rs"), ""),
		(include_str!("v1/mod.rs"), "/api/v1"),
		(include_str!("scim/mod.rs"), "/scim/v2"),
		(include_str!("oauth/mod.rs"), ""),
	] {
		all.extend(routes_in(source, prefix));
	}
	all
}

#[test]
fn every_route_declares_its_domain_rule() {
	let declared: BTreeSet<String> = RULES.iter().map(|rule| rule.pattern.to_string()).collect();
	assert_eq!(declared.len(), RULES.len(), "a pattern is listed twice");
	let registered = registered_routes();
	let undeclared: Vec<_> = registered.difference(&declared).collect();
	let stale: Vec<_> = declared.difference(&registered).collect();
	assert!(
		undeclared.is_empty(),
		"routes with no rule in RULES (decide how each treats a key confined to some domains): {undeclared:?}"
	);
	assert!(
		stale.is_empty(),
		"rules for routes that no router registers: {stale:?}"
	);
}

#[test]
fn every_rule_names_a_test_that_exists() {
	let mut sources = String::new();
	let mut pending = vec![std::path::PathBuf::from(concat!(
		env!("CARGO_MANIFEST_DIR"),
		"/src/api"
	))];
	while let Some(dir) = pending.pop() {
		for entry in std::fs::read_dir(&dir).expect("read src/api") {
			let path = entry.expect("entry").path();
			if path.is_dir() {
				pending.push(path);
			} else if path.extension().is_some_and(|ext| ext == "rs") {
				sources.push_str(&std::fs::read_to_string(&path).expect("read source"));
			}
		}
	}
	for rule in RULES {
		if rule.domain == Domain::Open {
			continue;
		}
		assert_ne!(rule.covered_by, "-", "{} needs a test", rule.pattern);
		let needle = format!("fn {}(", rule.covered_by);
		assert!(
			sources.contains(&needle),
			"{} is covered by {}, which does not exist",
			rule.pattern,
			rule.covered_by
		);
		assert!(!rule.scope.is_empty());
	}
}

/// The key scopes `RULES` gives `pattern` (`read/write` is two), or `None`
/// for a route it does not list. The OpenAPI tests hold their own scopes to it.
pub(super) fn scopes_of(pattern: &str) -> Option<BTreeSet<&'static str>> {
	RULES
		.iter()
		.find(|rule| rule.pattern == pattern)
		.map(|rule| {
			rule.scope
				.split('/')
				.filter(|scope| *scope != "none")
				.collect()
		})
}
