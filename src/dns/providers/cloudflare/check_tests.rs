use super::*;
use crate::dns::providers::check::Outcome;
use serde_json::json;

const ZONE_ID: &str = "11111111111111111111111111111111";
const OTHER_ID: &str = "22222222222222222222222222222222";

fn zones() -> Vec<Zone> {
	vec![Zone {
		id: ZONE_ID.into(),
		name: "example.org".into(),
	}]
}

fn policies(permission: &str, resource: &str) -> Vec<policy::Policy> {
	serde_json::from_value(json!([{
		"effect": "allow", "permission_groups": [{"name": permission}],
		"resources": {resource: "*"}
	}]))
	.unwrap()
}

#[test]
fn policy_verifies_write_and_zone_restriction_without_trial_write() {
	let zones = zones();
	let policies = policies(
		"DNS Write",
		&format!("com.cloudflare.api.account.zone.{ZONE_ID}"),
	);
	let (write, scope) = policy::findings(&policies, &zones, &[&zones[0]]);
	assert_eq!(write.status, Outcome::Verified);
	assert!(write.detail.contains("no write was attempted"));
	assert!(scope.detail.contains("restricted"));
}

#[test]
fn read_only_policy_does_not_imply_write() {
	let zones = zones();
	let policies = policies(
		"DNS Read",
		&format!("com.cloudflare.api.account.zone.{ZONE_ID}"),
	);
	let (write, _) = policy::findings(&policies, &zones, &[&zones[0]]);
	assert_eq!(write.status, Outcome::Failure);
	assert!(write.detail.contains("does not grant DNS Write"));
}

#[test]
fn policy_must_cover_each_required_zone() {
	let mut zones = zones();
	zones.push(Zone {
		id: OTHER_ID.into(),
		name: "example.net".into(),
	});
	let policies = policies(
		"DNS Write",
		&format!("com.cloudflare.api.account.zone.{ZONE_ID}"),
	);
	let (write, _) = policy::findings(&policies, &zones, &[&zones[0], &zones[1]]);
	assert_eq!(write.status, Outcome::Failure);
}

#[test]
fn wildcard_policy_is_broader_even_when_only_one_zone_is_visible() {
	let zones = zones();
	for resource in [
		"com.cloudflare.api.account.zone.*",
		"com.cloudflare.api.account.*",
	] {
		let policies = policies("DNS Write", resource);
		let (write, scope) = policy::findings(&policies, &zones, &[&zones[0]]);
		assert_eq!(write.status, Outcome::Verified);
		assert!(scope.detail.contains("account-wide or all-zone"));
	}
}

#[test]
fn deny_or_unknown_resource_policies_are_not_guessed() {
	let zones = zones();
	for value in [
		json!([{"effect":"deny", "permission_groups":[{"name":"DNS Write"}], "resources":{"com.cloudflare.api.account.zone.*":"*"}}]),
		json!([{"effect":"allow", "permission_groups":[{"name":"DNS Write"}], "resources":{"unfamiliar":"*"}}]),
		json!([{"effect":"allow", "permission_groups":[{}], "resources":{"com.cloudflare.api.account.zone.*":"*"}}]),
	] {
		let policies: Vec<policy::Policy> = serde_json::from_value(value).unwrap();
		let (write, scope) = policy::findings(&policies, &zones, &[&zones[0]]);
		assert_eq!(write.status, Outcome::NotVerifiable);
		assert_eq!(scope.status, Outcome::NotVerifiable);
	}
}

#[test]
fn zones_report_extra_and_missing_own_names() {
	let mut zones = zones();
	zones.push(Zone {
		id: OTHER_ID.into(),
		name: "extra.example".into(),
	});
	let names = vec![
		"mail.example.org".into(),
		"autoconfig.example.net".into(),
		"mta-sts.example.net".into(),
	];
	let (finding, needed) = zone_finding(&zones, &names);
	assert_eq!(finding.status, Outcome::Failure);
	assert_eq!(needed.len(), 1);
	assert!(finding.detail.contains("extra zones: extra.example"));
	assert!(
		finding
			.detail
			.contains("own names not visible: autoconfig.example.net, mta-sts.example.net")
	);
	let (_, scope) = policy::findings(
		&policies("DNS Write", "com.cloudflare.api.account.zone.*"),
		&zones,
		&needed,
	);
	assert!(scope.detail.contains("broader than needed"));
}

#[test]
fn zone_matching_uses_a_label_boundary_case_and_most_specific_zone() {
	let mut zones = zones();
	zones.push(Zone {
		id: OTHER_ID.into(),
		name: "sub.example.org".into(),
	});
	let (finding, needed) = zone_finding(&zones, &["MAIL.SUB.EXAMPLE.ORG.".into()]);
	assert_eq!(finding.status, Outcome::Verified);
	assert_eq!(needed[0].id, OTHER_ID);
	assert!(finding.detail.contains("extra zones: example.org"));
	let (finding, _) = zone_finding(&zones, &["badexample.org".into()]);
	assert_eq!(finding.status, Outcome::Failure);
}

#[test]
fn dates_distinguish_expired_near_and_unexposed_expiry() {
	let now = timestamp("2026-10-18T00:00:00Z").unwrap();
	assert_eq!(
		expiry(Some("2026-10-17T00:00:00Z"), now).status,
		Outcome::Failure
	);
	assert_eq!(
		expiry(Some("2026-10-18T00:00:00Z"), now).status,
		Outcome::Failure
	);
	let near = expiry(Some("2026-10-25T00:00:00Z"), now);
	assert_eq!(near.status, Outcome::Verified);
	assert!(near.detail.contains("within seven days"));
	assert!(
		!expiry(Some("2026-10-26T00:00:00Z"), now)
			.detail
			.contains("within seven days")
	);
	assert_eq!(expiry(None, now).status, Outcome::NotVerifiable);
	assert_eq!(expiry(Some("invalid"), now).status, Outcome::Failure);
}

#[test]
fn inactive_future_and_invalid_activation_are_failures() {
	let mut token = Token {
		id: ZONE_ID.into(),
		status: "active".into(),
		expires_on: None,
		not_before: None,
	};
	let now = timestamp("2026-10-18T00:00:00Z").unwrap();
	assert_eq!(token_finding(&token, now).status, Outcome::Verified);
	for status in ["expired", "disabled", "unrecognized"] {
		token.status = status.into();
		assert_eq!(token_finding(&token, now).status, Outcome::Failure);
	}
	token.status = "active".into();
	token.not_before = Some("2026-10-19T00:00:00Z".into());
	assert_eq!(token_finding(&token, now).status, Outcome::Failure);
	token.not_before = Some("invalid".into());
	assert_eq!(token_finding(&token, now).status, Outcome::Failure);
}

#[test]
fn invalid_dates_are_not_reported_as_verified() {
	for date in [
		"999999999999999999-01-01T00:00:00Z",
		"2026-02-30T00:00:00Z",
		"2026-10-18T00:00:99Z",
		"2026-10-18T00:00:00.Z",
		"2026-10-18T00:00:00+99:00",
		"2026-10-18T00:00:00",
	] {
		assert!(timestamp(date).is_none());
	}
	let now = timestamp("2026-10-18T00:00:00Z").unwrap();
	assert_eq!(timestamp("2026-10-18T01:00:00.125+01:00"), Some(now));
	let token = Token {
		id: ZONE_ID.into(),
		status: "active".into(),
		expires_on: Some("2026-10-17T00:00:00Z".into()),
		not_before: None,
	};
	assert_eq!(token_finding(&token, now).status, Outcome::Failure);
}
