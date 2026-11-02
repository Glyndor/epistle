use super::*;

#[tokio::test]
async fn delete_absent_record_is_idempotent_and_skips_refresh() {
	let (provider, state) = mock().await;
	// No matching record in the mock: find_record_id returns None, so we
	// never call DELETE or refresh.
	provider
		.delete("example.org", txt("_dmarc.example.org", "x"))
		.await
		.expect("delete");
	let s = state.lock().unwrap();
	assert_eq!(s.records.len(), 0);
	assert!(s.write_path.is_empty(), "no write call: {}", s.write_path);
	assert!(!s.refresh_called, "no refresh when nothing was deleted");
}

#[tokio::test]
async fn delete_present_record_calls_delete_then_refresh() {
	let existing = vec![StoredRecord {
		id: 7,
		field_type: "TXT".into(),
		sub_domain: "_dmarc".into(),
		target: "v=DMARC1".into(),
		ttl: 3600,
	}];
	let (provider, state) = mock_with(existing).await;
	provider
		.delete("example.org", txt("_dmarc.example.org", "v=DMARC1"))
		.await
		.expect("delete");
	let s = state.lock().unwrap();
	assert!(s.records.is_empty(), "delete removed the record");
	assert_eq!(s.write_method, "DELETE");
	assert_eq!(s.write_path, "/domain/zone/example.org/record/7");
	assert!(s.refresh_called, "POST /refresh must follow the delete");
}

/// A TXT delete with a value must drop only the matching record
/// and leave siblings at the same owner. Two ACME DNS-01 challenges
/// at the same owner is the canonical case: cleaning up one
/// certificate order's challenge must not wipe the second order's.
/// OVH's record store is per-id, so the fix is to find the id
/// whose target matches the value (not the first by (kind, sub))
/// and delete only that one. The records below intentionally put
/// the sibling first, so a regression that returns the first
/// record by (kind, sub) deletes the wrong id. OVH stores the
/// target quoted for TXT.
#[tokio::test]
async fn txt_delete_with_a_value_drops_only_the_matching_challenge() {
	let existing = vec![
		StoredRecord {
			id: 22,
			field_type: "TXT".into(),
			sub_domain: "_acme-challenge".into(),
			target: "\"token-bbbb\"".into(),
			ttl: 60,
		},
		StoredRecord {
			id: 21,
			field_type: "TXT".into(),
			sub_domain: "_acme-challenge".into(),
			target: "\"token-aaaa\"".into(),
			ttl: 60,
		},
	];
	let (provider, state) = mock_with(existing).await;
	provider
		.delete(
			"example.org",
			txt("_acme-challenge.example.org", "token-aaaa"),
		)
		.await
		.expect("delete one of two challenges");
	let s = state.lock().unwrap();
	assert_eq!(s.write_method, "DELETE");
	assert_eq!(
		s.write_path, "/domain/zone/example.org/record/21",
		"the matching id is deleted, not the sibling: path={}",
		s.write_path
	);
	assert!(s.refresh_called, "POST /refresh must follow the delete");
}

#[tokio::test]
async fn list_parses_records_and_strips_txt_quotes() {
	let existing = vec![
		StoredRecord {
			id: 11,
			field_type: "TXT".into(),
			sub_domain: "".into(),
			target: "\"v=spf1 -all\"".into(), // OVH silently quotes TXT.
			ttl: 3600,
		},
		StoredRecord {
			id: 12,
			field_type: "TXT".into(),
			sub_domain: "_dmarc".into(),
			target: "\"v=DMARC1; p=none\"".into(),
			ttl: 3600,
		},
	];
	let (provider, _state) = mock_with(existing).await;
	let records = provider.list("example.org").await.expect("list");
	assert_eq!(records.len(), 2);
	let apex = records
		.iter()
		.find(|r| r.name == "example.org")
		.expect("apex");
	assert_eq!(apex.kind, RecordKind::Txt);
	assert_eq!(apex.value, "v=spf1 -all");
	assert_eq!(apex.ttl, 3600);
	assert!(
		records
			.iter()
			.any(|r| r.name == "_dmarc.example.org" && r.value == "v=DMARC1; p=none")
	);
}

#[tokio::test]
async fn the_zone_search_goes_on_to_the_parent_when_the_child_zone_is_not_there() {
	// OVH holds no zone named `mail.example.org`: it answers 404, which
	// says the zone is not there, not that the provider could not answer.
	// The search goes on to the zone the credential covers.
	let (provider, _state) = mock().await;
	assert_eq!(
		crate::dns::zone::resolve(&provider, "mail.example.org")
			.await
			.expect("the search finds the parent zone"),
		"example.org"
	);
}
