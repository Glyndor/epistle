//! What the routes answer: the records of the configuration, and the checks
//! the resolver's answers give.

use std::sync::Arc;

use axum::http::StatusCode;

use super::fixture::*;

fn kinds(body: &serde_json::Value) -> Vec<(String, String)> {
	body["records"]
		.as_array()
		.expect("records")
		.iter()
		.map(|row| {
			(
				row["type"].as_str().unwrap().to_string(),
				row["name"].as_str().unwrap().to_string(),
			)
		})
		.collect()
}

#[tokio::test]
async fn the_groups_the_configuration_skips_are_counted_for_the_reach_of_the_key() {
	let world = world_with(
		"[dns_publish]\nskip = ['mta-sts']\n",
		Arc::new(Recording::default()),
	);
	let (_, all) = get(&world, "/api/v1/dns/records", READER).await;
	let (_, own) = get(&world, "/api/v1/dns/records", CONFINED).await;
	assert_eq!(
		all["skipped"],
		serde_json::json!([{"group": "mta-sts", "records": 6}])
	);
	assert_eq!(
		own["skipped"],
		serde_json::json!([{"group": "mta-sts", "records": 2}])
	);
	assert!(
		!kinds(&all)
			.iter()
			.any(|(_, name)| name.starts_with("_mta-sts.")),
		"a skipped group is not in the list"
	);
}

/// An input the server cannot read makes the list incomplete, and the answer
/// says so without naming the file.
#[tokio::test]
async fn an_unreadable_key_makes_the_list_incomplete_without_naming_the_file() {
	let world = world_with(
		"[dkim]\nselector = 'ed1'\nkey_file = '/nonexistent/dir/dkim-secret-name.pem'\n",
		Arc::new(Recording::default()),
	);
	let (status, body) = get(&world, "/api/v1/dns/records", READER).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["complete"], false);
	assert!(!body.to_string().contains("dkim-secret-name"), "{body}");
	assert!(!body.to_string().contains("/nonexistent"), "{body}");
	let (_, ordinary) = get(
		&world_with("", Arc::new(Recording::default())),
		"/api/v1/dns/records",
		READER,
	)
	.await;
	assert_eq!(ordinary["complete"], true);
}

/// With nothing published, the checks find records missing: the route reports
/// drift as an answer, not as an error.
#[tokio::test]
async fn drift_is_a_normal_answer() {
	let dns = Arc::new(Recording::default());
	let world = world_with("", dns.clone());
	let (status, body) = get(&world, "/api/v1/dns/verify", READER).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["ok"], false);
	let names: Vec<&str> = body["groups"]
		.as_array()
		.unwrap()
		.iter()
		.map(|group| group["name"].as_str().unwrap())
		.collect();
	assert_eq!(names, [HOST, "a.example", "b.example", "c.example"]);
	assert!(dns.names().iter().any(|name| name == "b.example"));
}

/// A confined key's check covers its own domains and asks the resolver
/// nothing about the mail host or the other tenants.
#[tokio::test]
async fn a_confined_check_looks_up_only_its_own_names() {
	let dns = Arc::new(Recording::default());
	let world = world_with("", dns.clone());
	let (status, body) = get(&world, "/api/v1/dns/verify", CONFINED).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let groups = body["groups"].as_array().unwrap();
	assert_eq!(groups.len(), 1, "{body}");
	assert_eq!(groups[0]["name"], "a.example");
	let asked = dns.names();
	assert!(!asked.is_empty());
	for name in &asked {
		assert!(
			name.ends_with("a.example") && name != HOST,
			"the resolver was asked about {name}"
		);
	}
}

/// Naming a domain checks that domain alone, and not the mail host.
#[tokio::test]
async fn naming_a_domain_checks_that_domain_alone() {
	let dns = Arc::new(Recording::default());
	let world = world_with("", dns.clone());
	let (status, body) = get(&world, "/api/v1/dns/verify?domain=c.example", token()).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["groups"].as_array().unwrap().len(), 1);
	assert!(dns.names().iter().all(|name| name.ends_with("c.example")));
}
