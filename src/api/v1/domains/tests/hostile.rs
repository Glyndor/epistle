//! Names in the path that are not a hosted domain's spelling. The route
//! compares the name as given, as `epistle domain show` does: only the ASCII
//! case of a hosted domain is forgiven, and nothing else reaches it.

use axum::http::StatusCode;

use super::fixture::{CONFINED, get, token, world};

/// Every one of these is answered `404 not_found`, by the configured token
/// and by a confined key alike.
const NOT_HOSTED: &[(&str, &str)] = &[
	("a trailing dot", "a.example."),
	("a leading dot", ".a.example"),
	("a leading space", "%20a.example"),
	("a trailing NUL", "a.example%00"),
	("a NUL alone", "%00"),
	(
		"the Unicode spelling of a hosted A-label",
		"b%C3%BCcher.example",
	),
	("a Cyrillic look-alike of a hosted name", "%D0%B0.example"),
	("a path traversal", "..%2F..%2Fetc%2Fpasswd"),
	("an encoded slash", "a.example%2Fb.example"),
	("a dot alone", "."),
	("a wildcard", "*.example"),
	("a hosted name as a subdomain", "x.a.example"),
	("a backslash", "a.example%5C"),
	("an address", "ann%40a.example"),
];

#[tokio::test]
async fn names_that_are_not_a_hosted_spelling_are_not_found() {
	let world = world();
	let long = format!("{}.example", "a".repeat(300));
	let mut cases: Vec<(&str, String)> = NOT_HOSTED
		.iter()
		.map(|(what, name)| (*what, (*name).to_string()))
		.collect();
	cases.push(("a name past 253 characters", long));
	for (what, name) in cases {
		for (who, bearer) in [("the token", token()), ("a confined key", CONFINED)] {
			let path = format!("/api/v1/domains/{name}");
			let (status, body) = get(&world, &path, bearer).await;
			assert_eq!(status, StatusCode::NOT_FOUND, "{what}, {who}: {body}");
			assert_eq!(
				body["error"]["code"], "not_found",
				"{what}, {who}: refused as not hosted, not for another reason: {body}"
			);
		}
	}
}

/// The ASCII case of a hosted domain is the domain: DNS names compare
/// without case. The answer names the domain as it was asked for, which is
/// what `epistle domain show` prints for the same argument.
#[tokio::test]
async fn upper_case_reaches_the_domain_and_is_echoed_as_asked() {
	let world = world();
	let (status, body) = get(&world, "/api/v1/domains/A.EXAMPLE", token()).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["domain"], "A.EXAMPLE");
	assert_eq!(body["quota"], 1000);
	let (status, body) = get(&world, "/api/v1/domains/A.Example", CONFINED).await;
	assert_eq!(status, StatusCode::OK, "its own domain in any case: {body}");
	let (status, _) = get(&world, "/api/v1/domains/B.EXAMPLE", CONFINED).await;
	assert_eq!(
		status,
		StatusCode::NOT_FOUND,
		"a foreign domain in another case is still foreign"
	);
}
