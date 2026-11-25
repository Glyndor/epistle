//! Who may read the DNS routes and what each key sees.

use std::sync::Arc;

use axum::http::StatusCode;

use super::fixture::*;

const ROUTES: [&str; 2] = ["/api/v1/dns/records", "/api/v1/dns/verify"];

#[tokio::test]
async fn a_request_without_a_credential_is_refused() {
	let world = world();
	for route in ROUTES {
		let (status, _, _) = get_with_headers(&world.state, route, None).await;
		assert_eq!(status, StatusCode::UNAUTHORIZED, "{route}");
		let (status, _, _) = get_with_headers(&world.state, route, Some("not-a-key")).await;
		assert_eq!(status, StatusCode::UNAUTHORIZED, "{route}");
	}
}

/// A key that is valid but holds neither `read` is turned away: the routes
/// are reads, so `write` and `send` do not open them.
#[tokio::test]
async fn a_key_without_the_read_scope_is_refused() {
	let dns = Arc::new(Recording::default());
	let world = world_with("", dns.clone());
	for route in ROUTES {
		for secret in [WRITER, SENDER] {
			let (status, body) = get(&world, route, secret).await;
			assert_eq!(status, StatusCode::FORBIDDEN, "{route}: {body}");
		}
	}
	assert!(dns.names().is_empty(), "nothing was looked up for them");
}

/// A key bound to one account has no business with the domains' DNS.
#[tokio::test]
async fn an_account_bound_key_is_refused() {
	let world = world();
	for route in ROUTES {
		let (status, body) = get(&world, route, BOUND).await;
		assert_eq!(status, StatusCode::FORBIDDEN, "{route}: {body}");
	}
}

#[tokio::test]
async fn the_unconfined_key_lists_every_domain_and_the_mail_host() {
	let world = world();
	let (status, body) = get(&world, "/api/v1/dns/records", READER).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let names: Vec<&str> = body["records"]
		.as_array()
		.expect("records")
		.iter()
		.map(|row| row["name"].as_str().expect("name"))
		.collect();
	for domain in ["a.example", "b.example", "c.example"] {
		assert!(
			names.contains(&format!("_dmarc.{domain}").as_str()),
			"{domain}"
		);
	}
	let host = body["records"]
		.as_array()
		.unwrap()
		.iter()
		.find(|row| row["name"] == HOST && row["type"] == "A")
		.expect("the address of the mail host");
	assert_eq!(host["value"], "192.0.2.10");
}

#[tokio::test]
async fn a_confined_key_lists_its_domains_and_not_the_mail_host() {
	let world = world();
	let (status, body) = get(&world, "/api/v1/dns/records", CONFINED).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let rows = body["records"].as_array().expect("records");
	assert!(!rows.is_empty());
	for row in rows {
		let name = row["name"].as_str().expect("name");
		assert!(
			name.ends_with("a.example"),
			"{name} is not under the key's domain"
		);
		assert!(
			row["type"] != "A" && row["type"] != "AAAA" && row["type"] != "TLSA",
			"{row}: a record of the mail host reached a confined key"
		);
		assert!(!row.to_string().contains("192.0.2.10"), "{row}");
	}
	assert!(!body.to_string().contains("b.example"));
	assert!(!body.to_string().contains("c.example"));
}

#[tokio::test]
async fn a_domain_of_another_tenant_answers_as_one_that_is_not_hosted() {
	let world = world();
	for route in ROUTES {
		let foreign = get(&world, &format!("{route}?domain=b.example"), CONFINED).await;
		let absent = get(&world, &format!("{route}?domain=nope.example"), CONFINED).await;
		assert_eq!(foreign.0, StatusCode::NOT_FOUND, "{route}: {}", foreign.1);
		assert_eq!(foreign, absent, "{route}: the status tells them apart");
		let unconfined = get(&world, &format!("{route}?domain=nope.example"), READER).await;
		assert_eq!(unconfined, absent, "{route}");
	}
}

#[tokio::test]
async fn naming_a_domain_gives_its_records_without_the_mail_host() {
	let world = world();
	let (status, body) = get(&world, "/api/v1/dns/records?domain=B.Example", token()).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let rows = body["records"].as_array().expect("records");
	assert!(
		rows.iter()
			.all(|row| row["name"].to_string().contains("b.example")),
		"{body}"
	);
	assert!(rows.iter().all(|row| row["type"] != "A"), "{body}");
	let (status, _) = get(&world, "/api/v1/dns/records?domain=A.EXAMPLE", CONFINED).await;
	assert_eq!(status, StatusCode::OK, "its own domain in any case");
}

/// A key confined to a domain the server does not host reaches nothing, and
/// nothing is read or looked up on its behalf.
#[tokio::test]
async fn a_key_confined_elsewhere_gets_an_empty_answer() {
	let dns = Arc::new(Recording::default());
	let world = world_with("", dns.clone());
	let (status, body) = get(&world, "/api/v1/dns/records", ELSEWHERE).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["records"], serde_json::json!([]));
	let (status, body) = get(&world, "/api/v1/dns/verify", ELSEWHERE).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body, serde_json::json!({"ok": true, "groups": []}));
	assert!(dns.names().is_empty(), "{:?}", dns.names());
}

/// Naming two domains must not widen what a confined key reaches.
#[tokio::test]
async fn a_repeated_domain_parameter_does_not_reach_the_second_name() {
	let world = world();
	for route in ROUTES {
		let (status, body) = get(
			&world,
			&format!("{route}?domain=a.example&domain=b.example"),
			CONFINED,
		)
		.await;
		assert!(
			!body.to_string().contains("b.example"),
			"{route}: {status} {body}"
		);
	}
}

/// Without the live configuration the routes have nothing to answer from,
/// and say so without guessing.
#[tokio::test]
async fn a_server_without_a_live_configuration_fails_closed() {
	let world = build(&three(), "", Arc::new(Recording::default()), false);
	for route in ROUTES {
		let (status, body) = get(&world, route, token()).await;
		assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{route}: {body}");
	}
}
