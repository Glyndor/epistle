use super::*;

#[tokio::test]
async fn create_carries_the_host_tag() {
	let (provider, state) = tagging_mock(Vec::new(), false).await;
	provider
		.upsert("example.org", txt("_dmarc.example.org", "v=DMARC1; p=none"))
		.await
		.expect("upsert");
	let body = body_at(&state, 0);
	assert_eq!(
		body["tags"],
		serde_json::json!(["epistle:mail.example.org"])
	);
	assert_eq!(body["comment"], expected_description());
}

#[tokio::test]
async fn update_replaces_the_epistle_tag_and_keeps_operator_tags() {
	let existing = vec![serde_json::json!({
		"id": "rec1", "type": "TXT", "name": "_dmarc.example.org",
		"content": "v=DMARC1; p=none", "ttl": 3600,
		"tags": ["team:mail", "epistle:old.example.org", "env:prod"]
	})];
	let (provider, state) = tagging_mock(existing, false).await;
	provider
		.upsert(
			"example.org",
			txt("_dmarc.example.org", "v=DMARC1; p=reject"),
		)
		.await
		.expect("upsert");
	assert!(
		state
			.lock()
			.unwrap()
			.calls
			.iter()
			.any(|c| c.starts_with("PUT "))
	);
	let body = body_at(&state, 0);
	assert_eq!(
		body["tags"],
		serde_json::json!(["team:mail", "env:prod", "epistle:mail.example.org"])
	);
	assert_eq!(body["comment"], expected_description());
}

#[tokio::test]
async fn refused_tags_retry_once_without_them_and_later_writes_skip_tags() {
	let (provider, state) = tagging_mock(Vec::new(), true).await;
	provider
		.upsert("example.org", txt("_dmarc.example.org", "v=DMARC1; p=none"))
		.await
		.expect("first upsert falls back to no tags");
	{
		let s = state.lock().unwrap();
		// One refused POST (not stored), one accepted POST without tags.
		let posts = s.calls.iter().filter(|c| *c == "POST /dns_records").count();
		assert_eq!(posts, 2, "{:?}", s.calls);
		assert_eq!(s.bodies.len(), 1);
	}
	let first = body_at(&state, 0);
	assert!(first.get("tags").is_none(), "{first}");
	assert_eq!(first["comment"], expected_description());
	provider
		.upsert("example.org", txt("_spf.example.org", "v=spf1 -all"))
		.await
		.expect("second upsert");
	let posts = state
		.lock()
		.unwrap()
		.calls
		.iter()
		.filter(|c| *c == "POST /dns_records")
		.count();
	assert_eq!(posts, 3, "second write must not try tags again");
}

#[tokio::test]
async fn accepted_tags_stay_on_for_later_writes() {
	let (provider, state) = tagging_mock(Vec::new(), false).await;
	provider
		.upsert("example.org", txt("_dmarc.example.org", "v=DMARC1; p=none"))
		.await
		.expect("upsert");
	provider
		.upsert("example.org", txt("_spf.example.org", "v=spf1 -all"))
		.await
		.expect("upsert");
	assert_eq!(
		body_at(&state, 1)["tags"],
		serde_json::json!(["epistle:mail.example.org"])
	);
}

#[tokio::test]
async fn without_a_hostname_no_tags_are_sent() {
	let (provider, state) = mock(Vec::new()).await;
	provider
		.upsert("example.org", txt("_dmarc.example.org", "v=DMARC1; p=none"))
		.await
		.expect("upsert");
	assert!(body_at(&state, 0).get("tags").is_none());
}
