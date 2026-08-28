//! Tests for the Google Cloud DNS provider. The mock, the generated key and
//! the shared helpers live in `gcloud_test_support.rs`.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use ring::signature::UnparsedPublicKey;
use serde_json::Value;

use super::test_support::*;
use super::*;

#[tokio::test]
async fn upsert_under_subdomain_posts_signed_change_with_quoted_txt() {
	let (base, state) = start_mock(Vec::new()).await;
	let provider = provider_for(&base);
	provider
		.upsert("example.org", txt("_dmarc.example.org", "v=DMARC1; p=none"))
		.await
		.expect("upsert");
	let s = state.lock().unwrap();
	let body = s.changes.last().expect("a change body");
	assert!(body.contains("\"name\":\"_dmarc.example.org.\""), "{body}");
	assert!(body.contains("\"type\":\"TXT\""), "{body}");
	// TXT rrdatas carry a quoted, escaped string.
	assert!(
		body.contains("\"rrdatas\":[\"\\\"v=DMARC1; p=none\\\"\"]"),
		"{body}"
	);
	// The provider obtained a bearer (from `/token`) and reused it.
	assert!(s.bearers.iter().all(|b| b.starts_with("Bearer ya29.test.")));
	// And the JWT was verified by `/token` — the assertion is captured here.
	assert!(
		s.last_assertion.as_deref().unwrap_or("").split('.').count() == 3,
		"last_assertion must be a JWT"
	);
	// The header declares the algorithm we signed with.
	let assertion = s.last_assertion.as_deref().unwrap();
	let header_b64 = assertion.split('.').next().unwrap();
	let header: Value = serde_json::from_slice(&B64URL.decode(header_b64).unwrap()).unwrap();
	assert_eq!(header["alg"], "RS256");
	assert_eq!(header["typ"], "JWT");
}

#[tokio::test]
async fn upsert_at_apex_uses_trailing_dot_zone_name() {
	let (base, state) = start_mock(Vec::new()).await;
	let provider = provider_for(&base);
	provider
		.upsert("example.org", txt("example.org", "v=spf1 -all"))
		.await
		.expect("upsert");
	let body = state.lock().unwrap().changes.last().unwrap().clone();
	assert!(body.contains("\"name\":\"example.org.\""), "{body}");
	assert!(body.contains("\"additions\":[{"), "{body}");
	assert!(body.contains("\"deletions\":[]"), "{body}");
}

#[tokio::test]
async fn upsert_existing_replaces_with_deletions_plus_additions() {
	let (base, state) = start_mock(Vec::new()).await;
	let provider = provider_for(&base);
	// Seed a pre-existing rrset so the next upsert must replace it.
	let initial = vec![Rrset {
		name: "_dmarc.example.org.".into(),
		kind: "TXT".into(),
		ttl: 300,
		rrdatas: vec!["\"old\"".into()],
	}];
	{
		let mut s = state.lock().unwrap();
		s.live_rrsets = initial.clone();
		s.rrsets = serde_json::json!({ "rrsets": initial });
	}
	provider
		.upsert("example.org", txt("_dmarc.example.org", "new-value"))
		.await
		.expect("upsert");
	let body = state.lock().unwrap().changes.last().unwrap().clone();
	// One change carries both the old (deletion) and the new (addition).
	assert!(body.contains("\"deletions\":[{"), "{body}");
	assert!(body.contains("\"rrdatas\":[\"\\\"old\\\"\"]"), "{body}");
	assert!(body.contains("\"additions\":[{"), "{body}");
	assert!(
		body.contains("\"rrdatas\":[\"\\\"new-value\\\"\"]"),
		"{body}"
	);
	// Calling upsert again with the same value must NOT submit a no-op change
	// (avoids the "two TXT for the same name" foot-gun).
	let before = state.lock().unwrap().changes.len();
	provider
		.upsert("example.org", txt("_dmarc.example.org", "new-value"))
		.await
		.expect("upsert");
	assert_eq!(
		state.lock().unwrap().changes.len(),
		before,
		"identical upsert must not submit another change"
	);
}

#[tokio::test]
async fn delete_is_idempotent_when_rrset_is_absent() {
	let (base, state) = start_mock(Vec::new()).await;
	let provider = provider_for(&base);
	provider
		.delete("example.org", txt("_dmarc.example.org", "x"))
		.await
		.expect("delete absent");
	assert!(
		state.lock().unwrap().changes.is_empty(),
		"no change should be submitted for an already-absent rrset"
	);
	// Now seed an rrset and verify a real delete fires.
	let initial = vec![Rrset {
		name: "_dmarc.example.org.".into(),
		kind: "TXT".into(),
		ttl: 300,
		rrdatas: vec!["\"old\"".into()],
	}];
	{
		let mut s = state.lock().unwrap();
		s.live_rrsets = initial;
	}
	provider
		.delete("example.org", txt("_dmarc.example.org", "x"))
		.await
		.expect("delete present");
	let body = state.lock().unwrap().changes.last().unwrap().clone();
	assert!(body.contains("\"deletions\":[{"), "{body}");
	assert!(body.contains("\"additions\":[]"), "{body}");
}

#[tokio::test]
async fn list_parses_rrsets_unquotes_txt_and_returns_fqdns() {
	let initial = vec![
		Rrset {
			name: "example.org.".into(),
			kind: "TXT".into(),
			ttl: 3600,
			rrdatas: vec!["\"v=spf1 -all\"".into()],
		},
		Rrset {
			name: "_dmarc.example.org.".into(),
			kind: "TXT".into(),
			ttl: 3600,
			rrdatas: vec!["\"v=DMARC1; p=none\"".into()],
		},
		Rrset {
			name: "mail.example.org.".into(),
			kind: "A".into(),
			ttl: 300,
			rrdatas: vec!["203.0.113.10".into()],
		},
		// A record under a different zone must be filtered out.
		Rrset {
			name: "mail.other.org.".into(),
			kind: "A".into(),
			ttl: 300,
			rrdatas: vec!["203.0.113.11".into()],
		},
	];
	let (base, _state) = start_mock(initial).await;
	let provider = provider_for(&base);
	let records = provider.list("example.org").await.expect("list");
	assert_eq!(records.len(), 3);
	let apex = records
		.iter()
		.find(|r| r.name == "example.org" && r.kind == RecordKind::Txt)
		.expect("apex TXT");
	assert_eq!(apex.value, "v=spf1 -all");
	assert!(
		records
			.iter()
			.any(|r| r.name == "_dmarc.example.org" && r.kind == RecordKind::Txt)
	);
	assert!(
		records
			.iter()
			.any(|r| r.name == "mail.example.org" && r.kind == RecordKind::A)
	);
	assert!(!records.iter().any(|r| r.name.ends_with("other.org")));
}

#[tokio::test]
async fn record_outside_zone_is_rejected_without_network() {
	let (base, state) = start_mock(Vec::new()).await;
	let provider = provider_for(&base);
	let result = provider
		.upsert("example.org", txt("_dmarc.other.example", "x"))
		.await;
	assert_eq!(result, Err(ProviderError::Auth));
	let s = state.lock().unwrap();
	assert!(s.changes.is_empty(), "no DNS API call must be made");
	// The token endpoint was also not contacted: there is no JWT to verify.
	assert!(s.last_assertion.is_none());
}

#[tokio::test]
async fn mx_upsert_passes_value_through_in_rrdatas() {
	let (base, state) = start_mock(Vec::new()).await;
	let provider = provider_for(&base);
	let mx = DnsRecord {
		name: "example.org".into(),
		kind: RecordKind::Mx,
		value: "10 mail.example.org.".into(),
		ttl: 3600,
	};
	provider.upsert("example.org", mx).await.expect("upsert");
	let body = state.lock().unwrap().changes.last().cloned().unwrap();
	// Cloud DNS carries MX as `<priority> <target>` in rrdatas (presentation
	// form, no quotes), per
	// https://cloud.google.com/dns/docs/records-overview.
	assert!(body.contains("\"type\":\"MX\""), "{body}");
	assert!(body.contains("\"rrdatas\":[\"10 mail.example.org.\"]"), "{body}");
}

#[tokio::test]
async fn srv_upsert_passes_value_through_in_rrdatas() {
	let (base, state) = start_mock(Vec::new()).await;
	let provider = provider_for(&base);
	let srv = DnsRecord {
		name: "_submissions._tcp.example.org".into(),
		kind: RecordKind::Srv,
		value: "0 1 465 mail.example.org.".into(),
		ttl: 3600,
	};
	provider.upsert("example.org", srv).await.expect("upsert");
	let body = state.lock().unwrap().changes.last().cloned().unwrap();
	// Cloud DNS carries SRV in rrdatas as `prio weight port target.`
	// (presentation form, no quotes), per
	// https://cloud.google.com/dns/docs/records-overview.
	assert!(body.contains("\"type\":\"SRV\""), "{body}");
	assert!(
		body.contains("\"rrdatas\":[\"0 1 465 mail.example.org.\"]"),
		"{body}"
	);
}

/// PEM round-trip: a valid PKCS#8 PEM decodes to a non-empty DER blob.
#[test]
fn pem_decoder_round_trips_a_pkcs8_block() {
	let key = test_key();
	assert!(key.pem.contains("BEGIN PRIVATE KEY"));
	let der = pem_to_pkcs8(&key.pem).expect("decode pem");
	assert!(!der.is_empty());
}

/// A malformed PEM returns `None`, not a panic.
#[test]
fn pem_decoder_rejects_garbage() {
	assert!(pem_to_pkcs8("not a pem at all").is_none());
	assert!(
		pem_to_pkcs8("-----BEGIN PRIVATE KEY-----\n!!!notbase64!!!\n-----END PRIVATE KEY-----")
			.is_none()
	);
}

/// RS256 sign+verify round-trip: a freshly signed token verifies against the
/// same test public key the mock uses.
#[test]
fn rs256_sign_then_verify() {
	let claims = serde_json::json!({
		"iss": "sa@example.iam.gserviceaccount.com",
		"scope": DNS_SCOPE,
		"aud": TOKEN_AUDIENCE,
		"iat": 1_000_000,
		"exp": 2_000_000,
	});
	let token = sign_rs256(&test_key().pem, &claims).expect("sign");
	let mut parts = token.split('.');
	let (h, p, s) = (
		parts.next().unwrap(),
		parts.next().unwrap(),
		parts.next().unwrap(),
	);
	assert_eq!(parts.next(), None);
	let header: Value = serde_json::from_slice(&B64URL.decode(h).unwrap()).unwrap();
	assert_eq!(header["alg"], "RS256");
	assert_eq!(header["typ"], "JWT");
	let payload: Value = serde_json::from_slice(&B64URL.decode(p).unwrap()).unwrap();
	assert_eq!(payload["iss"], "sa@example.iam.gserviceaccount.com");
	let sig2 = B64URL.decode(s).unwrap();
	UnparsedPublicKey::new(
		&ring::signature::RSA_PKCS1_2048_8192_SHA256,
		&test_key().pub_der,
	)
	.verify(format!("{h}.{p}").as_bytes(), &sig2)
	.expect("verify");
}
