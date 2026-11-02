use super::*;

/// Authorisation is case-insensitive on the zone and the owner name;
/// the FQDN-to-relative conversion has to follow the same rule or
/// `_dmarc.EXAMPLE.ORG` reaches the API as a full owner and the
/// apex absolute name `EXAMPLE.ORG` lands on the wrong path. Both
/// paths must agree, otherwise a DMARC publish with mixed case
/// either 401s (wrong path) or 404s (no such record set).
#[tokio::test]
async fn fqdn_to_relative_is_case_insensitive_on_the_zone_suffix() {
	let (provider, state) = mock().await;
	// Apex in upper case.
	provider
		.upsert(
			"example.org",
			DnsRecord::new("EXAMPLE.ORG", RecordKind::A, "203.0.113.10", 600),
		)
		.await
		.expect("apex upsert");
	// Sub-name in mixed case; the prefix is preserved, only the
	// zone suffix is matched case-insensitively.
	provider
		.upsert("example.org", txt("_DMARC.Example.Org", "v=DMARC1"))
		.await
		.expect("sub upsert");
	let s = state.lock().unwrap();
	assert_eq!(s.calls[1].path, "/domains/example.org/records/A/@");
	assert_eq!(s.calls[3].path, "/domains/example.org/records/TXT/_DMARC");
}

/// `list` reads the zone-wide endpoint, not the per-name one. The
/// relative names GoDaddy returns (`@`, `_dmarc`) are joined back to
/// FQDNs the rest of epistle expects.
#[tokio::test]
async fn list_parses_zone_records_and_emits_fqdn_names() {
	let zone_records = serde_json::json!([
		serde_json::json!({"type": "A", "name": "@", "data": "203.0.113.10", "ttl": 600}),
		serde_json::json!({"type": "TXT", "name": "_dmarc", "data": "v=DMARC1; p=none", "ttl": 600}),
		serde_json::json!({"type": "MX", "name": "@", "data": "mail.example.org.", "ttl": 600, "priority": 10}),
		serde_json::json!({"type": "SRV", "name": "_submissions._tcp", "data": "mail.example.org.", "ttl": 600, "priority": 0, "weight": 1, "port": 465}),
	]);
	let (provider, _state) = mock_with(zone_records).await;
	let listed = provider.list("example.org").await.expect("list");
	let apex = listed
		.iter()
		.find(|r| r.name == "example.org")
		.expect("apex");
	assert_eq!(apex.kind, RecordKind::A);
	assert_eq!(apex.value, "203.0.113.10");
	let dmarc = listed
		.iter()
		.find(|r| r.name == "_dmarc.example.org")
		.expect("dmarc");
	assert_eq!(dmarc.kind, RecordKind::Txt);
	assert_eq!(dmarc.value, "v=DMARC1; p=none");
	let mx = listed
		.iter()
		.find(|r| r.name == "example.org" && r.kind == RecordKind::Mx)
		.expect("mx");
	assert_eq!(mx.value, "10 mail.example.org");
	let srv = listed
		.iter()
		.find(|r| r.kind == RecordKind::Srv)
		.expect("srv");
	assert_eq!(srv.value, "0 1 465 mail.example.org");
}

/// GoDaddy returns names relative to the zone, always. A returned
/// name that happens to contain the zone suffix is still a
/// legitimate relative label, not an absolute FQDN. The previous
/// code's "ends with .zone" guess would resolve `mail.example.org`
/// as `mail.example.org` (the absolute name) when the API meant
/// `mail.example.org.example.org`. Round-tripping that record
/// through `delete` would then target `/records/{type}/mail`,
/// a different owner.
#[tokio::test]
async fn list_never_guesses_whether_a_returned_name_is_absolute() {
	let zone_records = serde_json::json!([
		// The API returned this name as a relative label; the
		// concatenation is the contract.
		serde_json::json!({"type": "A", "name": "mail.example.org", "data": "203.0.113.10", "ttl": 600}),
	]);
	let (provider, _state) = mock_with(zone_records).await;
	let listed = provider.list("example.org").await.expect("list");
	assert_eq!(listed.len(), 1);
	assert_eq!(
		listed[0].name, "mail.example.org.example.org",
		"a relative name is always joined to the zone, regardless of suffix"
	);
}

/// The SOA and a type GoDaddy publishes but epistle does not list as
/// itself keep their own kind. The old code turned every unknown type into
/// a TXT, so a round trip through `upsert` or `delete` would have acted on
/// the TXT set at the owner instead of the record the zone holds.
#[tokio::test]
async fn list_keeps_records_of_unpublished_kinds_as_themselves() {
	let zone_records = serde_json::json!([
		serde_json::json!({"type": "SOA", "name": "@", "data": "ns1.example.org. admin.example.org. 1 7200 3600 1209600 3600", "ttl": 600}),
		serde_json::json!({"type": "TXT", "name": "_dmarc", "data": "v=DMARC1", "ttl": 600}),
	]);
	let (provider, _state) = mock_with(zone_records).await;
	let listed = provider.list("example.org").await.expect("list");
	let kinds: Vec<RecordKind> = listed.iter().map(|r| r.kind.clone()).collect();
	assert_eq!(
		kinds,
		vec![RecordKind::Other("SOA".to_string()), RecordKind::Txt]
	);
	assert_eq!(listed[1].value, "v=DMARC1");
}
