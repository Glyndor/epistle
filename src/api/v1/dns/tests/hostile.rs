//! Names in `?domain=` that are not a hosted domain's spelling. Only the
//! ASCII case of a hosted domain is forgiven; nothing else reaches it.

use std::sync::Arc;

use axum::http::StatusCode;

use super::fixture::*;

const NOT_HOSTED: &[(&str, &str)] = &[
	("a trailing dot", "a.example."),
	("a leading dot", ".a.example"),
	("a leading space", "%20a.example"),
	("a trailing space", "a.example%20"),
	("a trailing NUL", "a.example%00"),
	("a NUL alone", "%00"),
	("a Cyrillic look-alike", "%D0%B0.example"),
	("a path traversal", "..%2F..%2Fetc%2Fpasswd"),
	("a slash", "a.example%2Fb.example"),
	("a wildcard", "*.example"),
	("a subdomain of a hosted name", "x.a.example"),
	("a backslash", "a.example%5C"),
	("an address", "ann%40a.example"),
	("a comma list", "a.example,b.example"),
	("a newline", "a.example%0Ab.example"),
	("an empty value", ""),
];

#[tokio::test]
async fn names_that_are_not_a_hosted_spelling_are_not_found() {
	let dns = Arc::new(Recording::default());
	let world = world_with("", dns.clone());
	let long = "a".repeat(10_000);
	let mut cases: Vec<(&str, String)> = NOT_HOSTED
		.iter()
		.map(|(what, name)| (*what, (*name).to_string()))
		.collect();
	cases.push(("a very long name", long));
	for (what, name) in cases {
		for route in ["/api/v1/dns/records", "/api/v1/dns/verify"] {
			for (who, bearer) in [("the token", token()), ("a confined key", CONFINED)] {
				let (status, body) = get(&world, &format!("{route}?domain={name}"), bearer).await;
				assert_eq!(
					status,
					StatusCode::NOT_FOUND,
					"{what}, {route}, {who}: {body}"
				);
			}
		}
	}
	assert!(
		dns.names().is_empty(),
		"no lookup for a name that is not hosted"
	);
}
