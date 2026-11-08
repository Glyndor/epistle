use super::*;

#[tokio::test]
async fn delete_absent_record_is_idempotent() {
	let (provider, state) = mock(Vec::new()).await;
	provider
		.delete(ZONE, txt("_dmarc.example.org", "x"))
		.await
		.expect("delete");
	let s = state.lock().unwrap();
	assert!(
		!s.calls.iter().any(|c| c.starts_with("DELETE")),
		"calls: {:?}",
		s.calls
	);
}

#[tokio::test]
async fn delete_existing_record_sends_delete_call() {
	let existing = vec![record(7, "_dmarc", "TXT", "v=DMARC1", 3600)];
	let (provider, state) = mock(existing).await;
	provider
		.delete(ZONE, txt("_dmarc.example.org", "v=DMARC1"))
		.await
		.expect("delete");
	let s = state.lock().unwrap();
	let deletes = s.calls.iter().filter(|c| c.starts_with("DELETE")).count();
	assert_eq!(deletes, 1, "calls: {:?}", s.calls);
}

/// A TXT delete with a value must drop only the matching record
/// and leave siblings at the same owner. Two ACME DNS-01 challenges
/// at the same owner is the canonical case: cleaning up one
/// certificate order's challenge must not wipe the second
/// order's. DNSimple addresses every record by id, so the fix is
/// to find the id whose content matches the value (not the first
/// by (name, kind)) and delete that one alone. The records below
/// intentionally put the sibling first, so a regression that
/// returns the first record by name+kind deletes the wrong id.
#[tokio::test]
async fn txt_delete_with_a_value_drops_only_the_matching_challenge() {
	let existing = vec![
		record(22, "_acme-challenge", "TXT", "token-bbbb", 60),
		record(21, "_acme-challenge", "TXT", "token-aaaa", 60),
	];
	let (provider, state) = mock(existing).await;
	provider
		.delete(ZONE, txt("_acme-challenge.example.org", "token-aaaa"))
		.await
		.expect("delete one of two challenges");
	let s = state.lock().unwrap();
	assert!(
		s.calls
			.iter()
			.any(|c| c == "DELETE /v2/{account}/zones/{zone}/records/21"),
		"the matching id is deleted: {:?}",
		s.calls
	);
	assert!(
		!s.calls
			.iter()
			.any(|c| c == "DELETE /v2/{account}/zones/{zone}/records/22"),
		"sibling id must not be deleted: {:?}",
		s.calls
	);
}
