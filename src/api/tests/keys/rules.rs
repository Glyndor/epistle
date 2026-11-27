//! Every HTTP route declares its rule: the scope a key needs and what it does
//! about the domains the key is confined to. The table below is the review
//! checklist for a new route; the first test fails when the routers and the
//! table disagree, so a route cannot be added without deciding its domain rule,
//! and the second fails when a row names a test that does not exist.

use std::collections::BTreeSet;

/// What a route does about a key confined to some domains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Domain {
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
	/// The `{domain}` of the path must be one of the key's domains, or the
	/// answer is the same `404` as for a domain the server does not host.
	HostedParam,
	/// Data shared by every tenant: refused to a confined key.
	Unconfined,
	/// The caller proves an account with its own credentials; no key is used.
	Credentials,
}

pub(super) struct Rule {
	/// The full path pattern as the router registers it.
	pub(super) pattern: &'static str,
	/// The key scope the route needs: `read`, `write`, `send`, `scim`, `alias` or `none`.
	pub(super) scope: &'static str,
	pub(super) domain: Domain,
	/// The test that proves the rule. `-` only for `Open` routes.
	pub(super) covered_by: &'static str,
}

pub(super) const fn rule(
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

pub(super) const RULES: &[Rule] = &[
	rule("/healthz", "none", Domain::Open, "-"),
	// The description of the API itself: no tenant data.
	rule("/api/v1/openapi.json", "manage:read", Domain::Open, "-"),
	// JMAP and send act for the principal behind the key.
	rule(
		"/.well-known/jmap",
		"mail:read",
		Domain::Principal,
		"scoped_key_session_lists_only_admissible_accounts",
	),
	rule(
		"/jmap/session",
		"mail:read",
		Domain::Principal,
		"scoped_key_session_lists_only_admissible_accounts",
	),
	rule(
		"/jmap/api",
		"mail:read/mail:write/send",
		Domain::Principal,
		"scoped_key_cannot_get_email_of_foreign_account",
	),
	rule(
		"/jmap/ws",
		"mail:read",
		Domain::Principal,
		"the_websocket_refuses_the_other_tenants_account",
	),
	rule(
		"/jmap/eventsource",
		"mail:read",
		Domain::Principal,
		"the_event_source_pushes_the_own_account_only",
	),
	rule(
		"/jmap/download/{account_id}/{blob_id}/{name}",
		"mail:read",
		Domain::Principal,
		"the_download_route_refuses_the_other_tenants_account",
	),
	rule(
		"/jmap/upload/{account_id}",
		"mail:write",
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
		"/api/v1/send/{id}",
		"manage:write/send",
		Domain::Principal,
		"another_accounts_key_gets_the_answer_for_an_id_that_does_not_exist",
	),
	rule(
		"/api/v1/deliveries",
		"mail:read/manage:read",
		Domain::Principal,
		"an_account_bound_key_only_sees_its_own_records",
	),
	// Management API.
	rule(
		"/api/v1/status",
		"manage:read",
		Domain::Filtered,
		"the_status_counters_cover_only_the_tenants_own_scope",
	),
	rule(
		"/api/v1/auth/verify",
		"manage:write",
		Domain::Filtered,
		"credential_verification_does_not_confirm_another_tenants_password",
	),
	rule(
		"/api/v1/health",
		"health",
		Domain::Unconfined,
		"a_confined_or_bound_key_is_refused_whatever_the_area",
	),
	rule(
		"/api/v1/health/{area}",
		"health",
		Domain::Unconfined,
		"a_confined_or_bound_key_is_refused_whatever_the_area",
	),
	rule(
		"/api/v1/bans",
		"ban",
		Domain::Unconfined,
		"a_confined_or_bound_key_is_refused_on_every_route",
	),
	rule(
		"/api/v1/bans/{subject}",
		"ban",
		Domain::Unconfined,
		"a_confined_or_bound_key_is_refused_on_every_route",
	),
	rule(
		"/api/v1/bans/allow",
		"ban",
		Domain::Unconfined,
		"a_confined_or_bound_key_is_refused_on_every_route",
	),
	rule(
		"/api/v1/bans/allow/{cidr}",
		"ban",
		Domain::Unconfined,
		"a_confined_or_bound_key_is_refused_on_every_route",
	),
	rule(
		"/api/v1/keys",
		"key",
		Domain::Filtered,
		"a_key_lists_and_revokes_only_the_keys_it_could_have_made",
	),
	rule(
		"/api/v1/keys/{label}",
		"key",
		Domain::Filtered,
		"a_key_lists_and_revokes_only_the_keys_it_could_have_made",
	),
	rule(
		"/api/v1/domains",
		"manage:read/manage:write",
		Domain::Filtered,
		"domain_creation_requires_an_unconfined_writer",
	),
	rule(
		"/api/v1/dns/records",
		"manage:read",
		Domain::Filtered,
		"a_confined_key_lists_its_domains_and_not_the_mail_host",
	),
	rule(
		"/api/v1/dns/verify",
		"manage:read",
		Domain::Filtered,
		"a_confined_check_looks_up_only_its_own_names",
	),
	rule(
		"/api/v1/domains/{domain}",
		"manage:read/manage:write",
		Domain::HostedParam,
		"domain_writes_are_confined_to_the_keys_domains",
	),
	rule(
		"/api/v1/domains/{domain}/enable",
		"manage:write",
		Domain::HostedParam,
		"domain_writes_are_confined_to_the_keys_domains",
	),
	rule(
		"/api/v1/domains/{domain}/disable",
		"manage:write",
		Domain::HostedParam,
		"domain_writes_are_confined_to_the_keys_domains",
	),
	rule(
		"/api/v1/domains/{domain}/aliases",
		"manage:write",
		Domain::HostedParam,
		"domain_aliases_require_both_names_in_scope",
	),
	rule(
		"/api/v1/domains/{domain}/aliases/{alias}",
		"manage:write",
		Domain::HostedParam,
		"domain_aliases_require_both_names_in_scope",
	),
	rule(
		"/api/v1/aliases",
		"alias",
		Domain::Filtered,
		"a_listing_shows_a_key_its_own_domains_and_the_configured_token_everything",
	),
	rule(
		"/api/v1/aliases/{alias}",
		"alias",
		Domain::Filtered,
		"a_remove_of_another_tenants_alias_is_as_absent_as_one_that_does_not_exist",
	),
	rule(
		"/api/v1/accounts",
		"manage:read/manage:write",
		Domain::Filtered,
		"a_scoped_key_lists_only_its_own_accounts",
	),
	rule(
		"/api/v1/accounts/{name}",
		"manage:write",
		Domain::AccountParam,
		"a_scoped_key_cannot_delete_another_tenants_account",
	),
	rule(
		"/api/v1/accounts/{name}/quota",
		"manage:write",
		Domain::Unconfined,
		"a_confined_key_does_not_set_a_quota_and_learns_nothing_of_the_account",
	),
	rule(
		"/api/v1/accounts/{name}/password",
		"manage:write",
		Domain::AccountParam,
		"a_scoped_key_cannot_reset_another_tenants_password",
	),
	rule(
		"/api/v1/accounts/{name}/display_name",
		"manage:write",
		Domain::AccountParam,
		"two_factor_and_display_name_of_another_tenants_account_are_out_of_reach",
	),
	rule(
		"/api/v1/accounts/{name}/totp",
		"manage:write",
		Domain::AccountParam,
		"two_factor_and_display_name_of_another_tenants_account_are_out_of_reach",
	),
	rule(
		"/api/v1/accounts/{name}/disable",
		"manage:write",
		Domain::AccountParam,
		"a_confined_key_suspends_the_accounts_of_its_own_domains_only",
	),
	rule(
		"/api/v1/accounts/{name}/enable",
		"manage:write",
		Domain::Unconfined,
		"a_confined_key_does_not_resume_an_account",
	),
	rule(
		"/api/v1/accounts/{name}/mailboxes",
		"manage:read",
		Domain::AccountParam,
		"a_scoped_key_cannot_list_another_tenants_mailboxes",
	),
	rule(
		"/api/v1/accounts/{name}/masked",
		"manage:read/manage:write",
		Domain::AccountParam,
		"masked_addresses_of_another_tenants_account_are_out_of_reach",
	),
	rule(
		"/api/v1/accounts/{name}/masked/{address}",
		"manage:write",
		Domain::AccountParam,
		"masked_addresses_of_another_tenants_account_are_out_of_reach",
	),
	rule(
		"/api/v1/accounts/{name}/archive",
		"manage:read",
		Domain::AccountParam,
		"the_archive_of_another_tenants_account_is_out_of_reach",
	),
	rule(
		"/api/v1/accounts/{name}/archive/{id}/restore",
		"manage:write",
		Domain::AccountParam,
		"the_archive_of_another_tenants_account_is_out_of_reach",
	),
	rule(
		"/api/v1/events",
		"manage:read",
		Domain::Filtered,
		"an_account_change_reaches_its_own_tenant_only",
	),
	rule(
		"/api/v1/queue",
		"manage:read",
		Domain::Filtered,
		"the_queue_lists_only_the_tenants_own_messages",
	),
	rule(
		"/api/v1/queue/destinations",
		"manage:read",
		Domain::Unconfined,
		"a_bound_key_is_refused_and_the_destinations_are_for_an_unconfined_key",
	),
	rule(
		"/api/v1/queue/{id}",
		"manage:read/manage:write",
		Domain::Filtered,
		"another_tenants_entry_answers_as_one_that_does_not_exist",
	),
	rule(
		"/api/v1/queue/{id}/retry",
		"manage:write",
		Domain::Filtered,
		"another_tenants_entry_answers_as_one_that_does_not_exist",
	),
	rule(
		"/api/v1/queue/{id}/hold",
		"manage:write",
		Domain::Filtered,
		"another_tenants_entry_answers_as_one_that_does_not_exist",
	),
	rule(
		"/api/v1/queue/{id}/release",
		"manage:write",
		Domain::Filtered,
		"another_tenants_entry_answers_as_one_that_does_not_exist",
	),
	rule(
		"/api/v1/suppression",
		"mail:read/mail:write/manage:read/manage:write",
		Domain::Unconfined,
		"the_shared_suppression_list_is_not_for_a_confined_key",
	),
	rule(
		"/api/v1/suppression/{address}",
		"mail:write/manage:write",
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
		"/oauth/revoke",
		"none",
		Domain::Credentials,
		"revocation_is_per_token_id_idempotent_and_survives_restart",
	),
	rule(
		"/oauth/authorize",
		"none",
		Domain::Credentials,
		"pkce_authorize_rejects_bad_credentials",
	),
];

pub(super) fn routes_in(source: &str, prefix: &str) -> BTreeSet<String> {
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

pub(super) fn registered_routes() -> BTreeSet<String> {
	let mut all = BTreeSet::new();
	for (source, prefix) in [
		(include_str!("../../mod.rs"), ""),
		(include_str!("../../v1/mod.rs"), "/api/v1"),
		(include_str!("../../scim/mod.rs"), "/scim/v2"),
		(include_str!("../../oauth/mod.rs"), ""),
	] {
		all.extend(routes_in(source, prefix));
	}
	all
}

pub(in crate::api) fn scopes_of(pattern: &str) -> Option<BTreeSet<&'static str>> {
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
