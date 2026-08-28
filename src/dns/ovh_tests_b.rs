//! OVH provider tests, second half. Split from `ovh_tests.rs` only to stay
//! under the per-file line limit; the harness lives in the first half.

use super::tests::{StoredRecord, mock, mock_with, txt};
use super::*;

#[tokio::test]
async fn record_outside_zone_is_rejected_without_network() {
	let (provider, state) = mock().await;
	let result = provider
		.upsert("example.org", txt("_dmarc.other.example", "x"))
		.await;
	assert_eq!(result, Err(ProviderError::Auth));
	// No request ever left the process.
	let s = state.lock().unwrap();
	assert_eq!(s.records.len(), 0);
	assert!(
		s.write_path.is_empty(),
		"unexpected request: {}",
		s.write_path
	);
	assert!(!s.refresh_called);
}

#[tokio::test]
async fn unsupported_kind_is_rejected() {
	let (provider, _state) = mock().await;
	let tlsa = DnsRecord {
		name: "_25._tcp.mail.example.org".into(),
		kind: RecordKind::Tlsa,
		value: "3 0 1 abcd".into(),
		ttl: 3600,
	};
	assert_eq!(
		provider.upsert("example.org", tlsa).await,
		Err(ProviderError::Unsupported)
	);
}

#[tokio::test]
async fn sign_recomputes_to_the_same_value() {
	let (provider, _state) = mock().await;
	let sig = provider.sign(
		"POST",
		"http://127.0.0.1:1/domain/zone/example.org/record",
		"{\"fieldType\":\"TXT\"}",
		1700000000,
	);
	assert!(sig.starts_with("$1$"), "{sig}");
	assert_eq!(sig.len(), "$1$".len() + 40);
	let again = provider.sign(
		"POST",
		"http://127.0.0.1:1/domain/zone/example.org/record",
		"{\"fieldType\":\"TXT\"}",
		1700000000,
	);
	assert_eq!(sig, again);
}

#[tokio::test]
async fn upsert_creates_caa_with_its_own_field_type() {
	// OVH was written before the CAA record existed, so `api_kind` did not
	// cover it and the compiler caught the gap. A CAA that never reaches the
	// zone is worse than silent: certificate issuance stays unrestricted
	// while the operator believes it is pinned to their CA.
	let (provider, state) = mock().await;
	provider
		.upsert(
			"example.org",
			DnsRecord {
				name: "example.org".into(),
				kind: RecordKind::Caa,
				value: "0 issue \"letsencrypt.org\"".into(),
				ttl: 3600,
			},
		)
		.await
		.expect("caa upsert");
	let (write_body, write_path) = {
		let s = state.lock().unwrap();
		(s.write_body.clone(), s.write_path.clone())
	};
	assert_eq!(write_path, "/domain/zone/example.org/record");
	let body: serde_json::Value = serde_json::from_str(&write_body).expect("body json");
	assert_eq!(body["fieldType"], "CAA");
	assert_eq!(body["subDomain"], "");
	assert_eq!(body["target"], "0 issue \"letsencrypt.org\"");
}

#[tokio::test]
async fn list_parses_a_caa_record_as_caa_and_not_as_txt() {
	// `parse_kind` falls back to TXT for anything it does not know, and the
	// compiler cannot catch a missing arm there. A CAA read back as TXT makes
	// `delete` look past the record it was asked to remove.
	let (provider, _state) = mock_with(vec![StoredRecord {
		id: 91,
		field_type: "CAA".into(),
		sub_domain: String::new(),
		target: "0 issue \"letsencrypt.org\"".into(),
		ttl: 3600,
	}])
	.await;
	let records = provider.list("example.org").await.expect("list");
	let caa = records
		.iter()
		.find(|r| r.value.contains("letsencrypt.org"))
		.expect("the CAA record is listed");
	assert_eq!(caa.kind, RecordKind::Caa);
}
