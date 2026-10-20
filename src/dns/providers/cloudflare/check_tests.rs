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
		"effect": "allow", "permission_groups": [{"name": permission, "id": match permission {
			"DNS Write" => "4755a26eedb94da69e1066d98aa820be",
			"DNS Read" => "82e64a83756745bbbb1c9c2701bf816b",
			_ => "unknown",
		}}],
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
		json!([{"effect":"deny", "permission_groups":[{"id":"4755a26eedb94da69e1066d98aa820be","name":"DNS Write"}], "resources":{"com.cloudflare.api.account.zone.*":"*"}}]),
		json!([{"effect":"allow", "permission_groups":[{"id":"4755a26eedb94da69e1066d98aa820be","name":"DNS Write"}], "resources":{"unfamiliar":"*"}}]),
		json!([{"effect":"allow", "permission_groups":[{}], "resources":{"com.cloudflare.api.account.zone.*":"*"}}]),
	] {
		let policies: Vec<policy::Policy> = serde_json::from_value(value).unwrap();
		let (write, scope) = policy::findings(&policies, &zones, &[&zones[0]]);
		assert_eq!(write.status, Outcome::NotVerifiable);
		assert_eq!(scope.status, Outcome::NotVerifiable);
	}
}

#[tokio::test]
async fn zones_report_extra_and_missing_own_names() {
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
	let (finding, needed) = zone_finding(&zones, &names, "").await;
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

#[tokio::test]
async fn zone_matching_uses_a_label_boundary_case_and_most_specific_zone() {
	let mut zones = zones();
	zones.push(Zone {
		id: OTHER_ID.into(),
		name: "sub.example.org".into(),
	});
	let (finding, needed) = zone_finding(&zones, &["MAIL.SUB.EXAMPLE.ORG.".into()], "").await;
	assert_eq!(finding.status, Outcome::Verified);
	assert_eq!(needed[0].id, OTHER_ID);
	assert!(finding.detail.contains("extra zones: example.org"));
	let (finding, _) = zone_finding(&zones, &["badexample.org".into()], "").await;
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

#[test]
fn unknown_permission_never_establishes_scope() {
	let zones = zones();
	for permission in ["Future DNS Admin", "", "DNS Write renamed"] {
		let policies = policies(permission, "com.cloudflare.api.account.zone.*");
		let (write, scope) = policy::findings(&policies, &zones, &[&zones[0]]);
		assert_eq!(scope.status, Outcome::NotVerifiable);
		assert_eq!(write.status, Outcome::NotVerifiable);
	}
}

#[tokio::test]
async fn zone_report_never_reflects_credential_fragments() {
	let token = crate::test_fixtures::bytes::<20>()
		.iter()
		.map(|b| format!("{b:02x}"))
		.collect::<String>();
	for fragment in [token.as_str(), &token[..8], &token[token.len() - 8..]] {
		for name in [
			format!("{fragment}.example"),
			format!("{}.example", fragment.to_ascii_uppercase()),
		] {
			let zones = vec![Zone {
				id: ZONE_ID.into(),
				name: name.clone(),
			}];
			for names in [
				vec![format!("mail.{name}")],
				vec![format!("mail.{name}.missing.test")],
			] {
				let (finding, _) = zone_finding(&zones, &names, &token).await;
				let mut report = AccessReport::unknown();
				report.zones = finding;
				let json = serde_json::to_string(&report).unwrap();
				for output in [report.zones.detail.as_str(), json.as_str()] {
					assert!(
						!output
							.to_ascii_lowercase()
							.contains(&fragment.to_ascii_lowercase()),
						"zone report disclosed a credential fragment"
					);
				}
			}
		}
	}
}

#[tokio::test]
async fn thousands_of_zones_use_linear_matching_work() {
	let count = 4000;
	let zones = (0..count)
		.map(|i| Zone {
			id: format!("{i:032x}"),
			name: format!("d{i}.example"),
		})
		.collect::<Vec<_>>();
	let names = zones
		.iter()
		.map(|z| format!("mail.{}", z.name))
		.collect::<Vec<_>>();
	MATCH_WORK.with(|work| work.set(0));
	let (finding, needed) = zone_finding(&zones, &names, "").await;
	assert_eq!(finding.status, Outcome::Verified);
	assert_eq!(needed.len(), count);
	assert!(
		MATCH_WORK.with(|work| work.get()) <= count * 4,
		"zone matching exceeded a linear lookup budget"
	);
}

#[tokio::test]
async fn inspection_refuses_excessive_own_names() {
	let names = vec!["mail.example.org".into(); 16_385];
	let zones = zones();
	let (finding, needed) = zone_finding(&zones, &names, "").await;
	assert_eq!(finding.status, Outcome::Failure);
	assert!(needed.is_empty());
}

#[test]
fn permission_ids_define_grants_instead_of_display_names() {
	let zones = zones();
	for (id, name, expected) in [
		(
			"4755a26eedb94da69e1066d98aa820be",
			"DNS permission renamed",
			Outcome::Verified,
		),
		("unknown", "DNS Write", Outcome::NotVerifiable),
		(
			"c8fed203ed3043cba015a93ad1616f1f",
			"Zone Read",
			Outcome::Failure,
		),
	] {
		let policies = serde_json::from_value::<Vec<policy::Policy>>(json!([{
			"effect":"allow", "permission_groups":[{"id":id,"name":name}],
			"resources":{format!("com.cloudflare.api.account.zone.{ZONE_ID}"):"*"}
		}]))
		.unwrap();
		let (write, scope) = policy::findings(&policies, &zones, &[&zones[0]]);
		assert_eq!(write.status, expected);
		assert_eq!(
			scope.status,
			if expected == Outcome::NotVerifiable {
				Outcome::NotVerifiable
			} else {
				Outcome::Verified
			}
		);
	}
}

#[tokio::test]
async fn matching_cooperates_with_the_operation_deadline() {
	use crate::dns::providers::{TEST_OPERATION_DEADLINE, within};
	let zones = (0..4000)
		.map(|i| Zone {
			id: format!("{i:032x}"),
			name: format!("d{i}.example"),
		})
		.collect::<Vec<_>>();
	let names = zones
		.iter()
		.map(|z| format!("mail.{}", z.name))
		.collect::<Vec<_>>();
	TEST_OPERATION_DEADLINE.with(|limit| limit.set(Some(std::time::Duration::ZERO)));
	let result = within(async { Ok(zone_finding(&zones, &names, "").await) }).await;
	TEST_OPERATION_DEADLINE.with(|limit| limit.set(None));
	assert!(
		result.is_err(),
		"CPU matching must yield to the operation deadline"
	);
}
