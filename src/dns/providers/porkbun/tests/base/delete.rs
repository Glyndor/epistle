use super::*;

#[tokio::test]
async fn deleting_an_absent_record_succeeds() {
	let (provider, state) = mock(serde_json::json!([stored(
		"106926654",
		"example.org",
		"TXT",
		"v=spf1 mx -all"
	)]))
	.await;
	provider
		.delete("example.org", txt("_dmarc.example.org", "v=DMARC1; p=none"))
		.await
		.expect("delete is idempotent");
	let s = state.lock().unwrap();
	assert_eq!(s.paths(), vec!["/dns/retrieve/example.org"]);
}

#[tokio::test]
async fn delete_removes_the_matching_record_by_id() {
	let (provider, state) = mock(serde_json::json!([stored(
		"106926652",
		"_dmarc.example.org",
		"TXT",
		"v=DMARC1; p=none"
	)]))
	.await;
	provider
		.delete("example.org", txt("_dmarc.example.org", "v=DMARC1; p=none"))
		.await
		.expect("delete");
	let s = state.lock().unwrap();
	assert_eq!(
		s.paths(),
		vec![
			"/dns/retrieve/example.org",
			"/dns/delete/example.org/106926652"
		]
	);
	let body = s.body("/dns/delete/example.org/106926652");
	// `assert_eq!` on the API key / secret JSON value would
	// Debug-print the value on a mismatch, dumping the
	// credential into the CI log. The boolean form names
	// the contract without echoing the payload.
	assert!(
		body["apikey"] == "pk1_apikey",
		"porkbun POST body must carry the API key"
	);
	assert!(
		body["secretapikey"] == "sk1_secret",
		"porkbun POST body must carry the API secret"
	);
}

/// A TXT delete with a value must remove only the matching record and
/// leave siblings at the same owner alone. Two ACME DNS-01 challenges
/// at the same owner is the canonical case: cleaning up one certificate
/// order's challenge must not wipe the second order's challenge.
/// Porkbun addresses each record by numeric id, so the fix is to read
/// the live set, drop the rows whose content matches the value, and
/// delete only those ids.
#[tokio::test]
async fn txt_delete_with_a_value_keeps_the_sibling_challenge() {
	let (provider, state) = mock(serde_json::json!([
		stored(
			"106926652",
			"_acme-challenge.example.org",
			"TXT",
			"token-aaaa"
		),
		stored(
			"106926653",
			"_acme-challenge.example.org",
			"TXT",
			"token-bbbb"
		),
	]))
	.await;
	provider
		.delete(
			"example.org",
			txt("_acme-challenge.example.org", "token-aaaa"),
		)
		.await
		.expect("delete one of two challenges");
	let s = state.lock().unwrap();
	assert_eq!(
		s.paths(),
		vec![
			"/dns/retrieve/example.org",
			"/dns/delete/example.org/106926652"
		],
		"only the matching value's id is deleted, the sibling survives"
	);
}
