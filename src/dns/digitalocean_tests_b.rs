//! DigitalOcean provider tests for the record types with structured RDATA.
//! Split from `digitalocean_tests.rs` for the per-file line limit; the mock
//! lives in the first half.
//!
//! SRV, CAA and MX are the ones worth pinning: DigitalOcean does not take a
//! presentation-form string for them, it takes dedicated JSON fields, so a
//! provider that got the split wrong publishes a syntactically valid record
//! that means something else.

use super::tests::mock;
use super::*;

fn record(name: &str, kind: RecordKind, value: &str) -> DnsRecord {
	DnsRecord {
		name: name.to_string(),
		kind,
		value: value.to_string(),
		ttl: 3600,
	}
}

#[tokio::test]
async fn srv_upsert_splits_priority_weight_port_and_target() {
	let (provider, state) = mock(Vec::new(), false).await;
	provider
		.upsert(
			"example.org",
			record(
				"_submissions._tcp.example.org",
				RecordKind::Srv,
				"10 5 465 mail.example.org",
			),
		)
		.await
		.expect("srv upsert");
	let body = state.lock().unwrap().bodies.last().expect("body").clone();
	assert!(body.contains("\"type\":\"SRV\""), "{body}");
	assert!(body.contains("\"priority\":10"), "{body}");
	assert!(body.contains("\"weight\":5"), "{body}");
	assert!(body.contains("\"port\":465"), "{body}");
	assert!(body.contains("\"data\":\"mail.example.org\""), "{body}");
}

#[tokio::test]
async fn a_malformed_srv_value_is_refused_rather_than_published() {
	let (provider, _state) = mock(Vec::new(), false).await;
	let error = provider
		.upsert(
			"example.org",
			record("_x._tcp.example.org", RecordKind::Srv, "not an srv"),
		)
		.await
		.expect_err("a value we cannot split must not be sent");
	assert!(matches!(error, ProviderError::Remote(_)), "{error:?}");
}

#[tokio::test]
async fn caa_upsert_splits_flags_tag_and_value() {
	let (provider, state) = mock(Vec::new(), false).await;
	provider
		.upsert(
			"example.org",
			record(
				"example.org",
				RecordKind::Caa,
				"0 issue \"letsencrypt.org\"",
			),
		)
		.await
		.expect("caa upsert");
	let body = state.lock().unwrap().bodies.last().expect("body").clone();
	assert!(body.contains("\"type\":\"CAA\""), "{body}");
	assert!(body.contains("\"priority\":0"), "{body}");
	assert!(body.contains("\"tag\":\"issue\""), "{body}");
	// The quotes belong to the presentation form, not to the value itself.
	assert!(body.contains("\"data\":\"letsencrypt.org\""), "{body}");
}

#[tokio::test]
async fn a_caa_value_missing_a_field_is_refused() {
	let (provider, _state) = mock(Vec::new(), false).await;
	let error = provider
		.upsert(
			"example.org",
			record("example.org", RecordKind::Caa, "0 issue"),
		)
		.await
		.expect_err("an incomplete CAA must not be sent");
	assert!(matches!(error, ProviderError::Remote(_)), "{error:?}");
}

#[tokio::test]
async fn mx_upsert_splits_preference_from_exchange() {
	let (provider, state) = mock(Vec::new(), false).await;
	provider
		.upsert(
			"example.org",
			record("example.org", RecordKind::Mx, "10 mail.example.org"),
		)
		.await
		.expect("mx upsert");
	let body = state.lock().unwrap().bodies.last().expect("body").clone();
	assert!(body.contains("\"type\":\"MX\""), "{body}");
	assert!(body.contains("\"priority\":10"), "{body}");
	assert!(body.contains("\"data\":\"mail.example.org\""), "{body}");
}

#[tokio::test]
async fn delete_removes_the_matching_record_by_id() {
	let existing = vec![serde_json::json!({
		"id": 4242u64,
		"type": "TXT",
		"name": "_dmarc",
		"data": "v=DMARC1; p=none",
		"ttl": 3600,
	})];
	let (provider, state) = mock(existing, false).await;
	provider
		.delete(
			"example.org",
			record("_dmarc.example.org", RecordKind::Txt, "v=DMARC1; p=none"),
		)
		.await
		.expect("delete");
	let calls = state.lock().unwrap().calls.clone();
	assert!(
		calls
			.iter()
			.any(|c| c == "DELETE /v2/domains/example.org/records/4242"),
		"calls: {calls:?}"
	);
}
