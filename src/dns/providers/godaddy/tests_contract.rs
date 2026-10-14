//! The upsert contract against the GoDaddy mock: a TXT upsert replaces
//! the record of the same purpose and leaves every other TXT at the name
//! alone. Two records of the same purpose at the same name are a
//! configuration mistake (SPF returns `permerror`, RFC 7208 §4.5; DMARC
//! is ignored, RFC 7489 §6.6.3), so the upsert collapses them into one
//! carrying the new value. A zone that starts with two `v=spf1` TXT
//! plus one unrelated TXT ends with exactly one SPF TXT (epistle's
//! value) and the unrelated TXT untouched.

use super::tests::{mock_with_per_name, txt};
use super::*;
use axum::http::Method;

#[tokio::test]
async fn txt_upsert_collapses_duplicates_of_the_same_purpose() {
	const OLD_SPF_1: &str = "v=spf1 mx -all";
	const OLD_SPF_2: &str = "v=spf1 include:_spf.google.com -all";
	const NEW_SPF: &str = "v=spf1 -all";
	const UNRELATED: &str = "google-site-verification=abc123";
	let mut per_name = std::collections::HashMap::new();
	per_name.insert(
		("TXT".to_string(), "@".to_string()),
		serde_json::json!([
			{"data": OLD_SPF_1, "ttl": 3600},
			{"data": OLD_SPF_2, "ttl": 3600},
			{"data": UNRELATED, "ttl": 3600},
		]),
	);
	let (provider, state) = mock_with_per_name(serde_json::json!([]), per_name).await;
	provider
		.upsert("example.org", txt("example.org", NEW_SPF))
		.await
		.expect("apex SPF upsert with duplicates");
	let s = state.lock().unwrap();
	// One write: the GET (read live set) + the PUT (replace with
	// collapsed set). No DELETE: GoDaddy writes the new rrset in
	// place rather than touching individual ids.
	let put_bodies: Vec<&str> = s
		.calls
		.iter()
		.filter(|c| c.method == Method::PUT)
		.map(|c| c.body.as_str())
		.collect();
	assert_eq!(
		put_bodies.len(),
		1,
		"exactly one PUT body, got {} calls",
		s.calls.len()
	);
	let body: serde_json::Value = serde_json::from_str(put_bodies[0]).expect("JSON");
	let arr = body.as_array().expect("body is a JSON array");
	assert_eq!(
		arr.len(),
		2,
		"exactly one SPF + one unrelated record after the upsert: {arr:?}"
	);
	let data: Vec<&str> = arr
		.iter()
		.map(|e| e["data"].as_str().expect("data string"))
		.collect();
	assert!(
		data.contains(&NEW_SPF),
		"new SPF present in the body: {data:?}"
	);
	assert!(
		!data.contains(&OLD_SPF_1),
		"old SPF1 was re-published: {data:?}"
	);
	assert!(
		!data.contains(&OLD_SPF_2),
		"old SPF2 was re-published: {data:?}"
	);
	assert!(
		data.contains(&UNRELATED),
		"the unrelated TXT was lost: {data:?}"
	);
}
