//! Tests for the Route 53 provider: the SigV4 signature against AWS's
//! documented example, timestamp formatting, and the request against a mock.

use super::*;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::State;
use axum::routing::{get, post};

#[test]
fn sigv4_signature_matches_aws_example() {
	// AWS SigV4 documentation, "Task 3: Calculate the signature".
	let string_to_sign = "AWS4-HMAC-SHA256\n\
20150830T123600Z\n\
20150830/us-east-1/iam/aws4_request\n\
f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59";
	let sig = signature(
		"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		"20150830",
		"us-east-1",
		"iam",
		string_to_sign,
	);
	assert_eq!(
		sig,
		"5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
	);
}

#[test]
fn timestamps_format_utc() {
	assert_eq!(
		timestamps(0),
		("19700101T000000Z".to_string(), "19700101".to_string())
	);
	// 1_000_000_000 = 2001-09-09T01:46:40Z.
	assert_eq!(
		timestamps(1_000_000_000),
		("20010909T014640Z".to_string(), "20010909".to_string())
	);
}

#[derive(Default)]
pub(super) struct MockState {
	pub(super) bodies: Vec<String>,
	pub(super) auth: Option<String>,
	/// Preloaded response for the LIST endpoint; when `None`, the
	/// mock returns an empty resource record set list.
	pub(super) list_response: Option<String>,
}

pub(super) type Shared = Arc<Mutex<MockState>>;

pub(super) const TOKEN_A: &str = "token-aaaa";
pub(super) const TOKEN_B: &str = "token-bbbb";

async fn change(
	State(state): State<Shared>,
	headers: axum::http::HeaderMap,
	body: String,
) -> &'static str {
	let mut s = state.lock().unwrap();
	s.auth = headers
		.get("authorization")
		.and_then(|v| v.to_str().ok())
		.map(str::to_string);
	s.bodies.push(body);
	"<ChangeResourceRecordSetsResponse/>"
}

async fn list_rrsets(
	State(state): State<Shared>,
	headers: axum::http::HeaderMap,
) -> axum::http::Response<String> {
	let mut s = state.lock().unwrap();
	s.auth = headers
		.get("authorization")
		.and_then(|v| v.to_str().ok())
		.map(str::to_string);
	let body = s.list_response.clone().unwrap_or_else(|| {
		r#"<?xml version="1.0" encoding="UTF-8"?><ListResourceRecordSetsResult><ResourceRecordSets/></ListResourceRecordSetsResult>"#.to_string()
	});
	axum::http::Response::builder()
		.status(200)
		.header("content-type", "text/xml")
		.body(body)
		.expect("build list response")
}

pub(super) async fn mock() -> (Route53Provider, Shared) {
	let state: Shared = Arc::new(Mutex::new(MockState::default()));
	let app = Router::new()
		.route(
			"/2013-04-01/hostedzone/{id}/rrset",
			post(change).get(list_rrsets),
		)
		.with_state(state.clone());
	#[allow(unused_imports)]
	use {get, post};
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		let _ = axum::serve(listener, app).await;
	});
	let provider = Route53Provider::new("AKIA".into(), "secret".into(), "Z123".into())
		.with_base(format!("http://{addr}"));
	(provider, state)
}

#[tokio::test]
async fn upsert_sends_signed_change_request() {
	let (provider, state) = mock().await;
	let record = DnsRecord {
		name: "_dmarc.example.org".into(),
		kind: RecordKind::Txt,
		value: "v=DMARC1; p=none".into(),
		ttl: 3600,
	};
	provider
		.upsert("example.org", record)
		.await
		.expect("upsert");
	let s = state.lock().unwrap();
	let body = &s.bodies[0];
	assert!(body.contains("<Action>UPSERT</Action>"), "{body}");
	assert!(body.contains("<Type>TXT</Type>"), "{body}");
	// TXT value is quoted.
	assert!(body.contains("v=DMARC1; p=none"), "{body}");
	// SigV4 Authorization header is attached.
	let auth = s.auth.as_deref().unwrap_or("");
	assert!(
		auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIA/"),
		"{auth}"
	);
	assert!(auth.contains("SignedHeaders=host;x-amz-date"), "{auth}");
}

#[tokio::test]
async fn delete_uses_delete_action() {
	let (provider, state) = mock().await;
	// Seed the LIST mock with a TXT rrset at the matching name so
	// the value-bearing delete path takes the wholesale DELETE
	// branch (the rrset's only rdata is the value being removed).
	{
		let mut s = state.lock().unwrap();
		s.list_response = Some(
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<ListResourceRecordSetsResult>\
<ResourceRecordSets>\
<ResourceRecordSet>\
<Name>_dmarc.example.org.</Name><Type>TXT</Type><TTL>3600</TTL>\
<ResourceRecords>\
<ResourceRecord><Value>\"v=DMARC1; p=none\"</Value></ResourceRecord>\
</ResourceRecords>\
</ResourceRecordSet>\
</ResourceRecordSets>\
</ListResourceRecordSetsResult>"
				.to_string(),
		);
	}
	let record = DnsRecord {
		name: "_dmarc.example.org".into(),
		kind: RecordKind::Txt,
		value: "v=DMARC1; p=none".into(),
		ttl: 3600,
	};
	provider
		.delete("example.org", record)
		.await
		.expect("delete");
	let s = state.lock().unwrap();
	// The value-bearing path LISTs (GET, not captured) then DELETEs
	// (POST, captured); the only body the mock sees is the DELETE.
	assert_eq!(s.bodies.len(), 1);
	assert!(s.bodies[0].contains("<Action>DELETE</Action>"));
}

/// A TXT delete with a value must drop only the matching rdata and
/// keep sibling TXT records at the same owner. Two ACME DNS-01
/// challenges at the same owner is the canonical case. Route 53
/// DELETE on an RRset is wholesale (it matches Name+Type only), so
/// the value-bearing case LISTs the RRset, drops the matching
/// rdata, and UPSERTs the remainder. The empty-value retire path
/// keeps the existing wholesale DELETE.
#[tokio::test]
async fn txt_delete_with_a_value_keeps_the_sibling_challenge() {
	let (provider, state) = mock().await;
	// Preload the LIST mock with a TXT rrset at _acme-challenge
	// carrying two distinct rrdatas.
	{
		let mut s = state.lock().unwrap();
		s.list_response = Some(format!(
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<ListResourceRecordSetsResult>\
<ResourceRecordSets>\
<ResourceRecordSet>\
<Name>_acme-challenge.example.org.</Name><Type>TXT</Type><TTL>60</TTL>\
<ResourceRecords>\
<ResourceRecord><Value>\"{TOKEN_A}\"</Value></ResourceRecord>\
<ResourceRecord><Value>\"{TOKEN_B}\"</Value></ResourceRecord>\
</ResourceRecords>\
</ResourceRecordSet>\
</ResourceRecordSets>\
</ListResourceRecordSetsResult>"
		));
	}
	provider
		.delete(
			"example.org",
			DnsRecord {
				name: "_acme-challenge.example.org".into(),
				kind: RecordKind::Txt,
				value: "token-aaaa".into(),
				ttl: 60,
			},
		)
		.await
		.expect("delete one of two challenges");
	let s = state.lock().unwrap();
	let body = &s.bodies[s.bodies.len() - 1];
	// The change is an UPSERT (not a wholesale DELETE) that
	// replaces the RRset with the surviving rdata only.
	assert!(body.contains("<Action>UPSERT</Action>"), "{body}");
	assert!(body.contains(TOKEN_B), "sibling rdata missing: {body}");
	assert!(
		!body.contains(TOKEN_A),
		"matching rdata leaked into the UPSERT: {body}"
	);
}

#[tokio::test]
async fn mx_upsert_uses_verbatim_value_in_value_element() {
	let (provider, state) = mock().await;
	let mx = DnsRecord {
		name: "example.org".into(),
		kind: RecordKind::Mx,
		value: "10 mail.example.org".into(),
		ttl: 3600,
	};
	provider.upsert("example.org", mx).await.expect("upsert");
	let body = state.lock().unwrap().bodies[0].clone();
	assert!(body.contains("<Type>MX</Type>"), "{body}");
	assert!(
		body.contains("<Value>10 mail.example.org</Value>"),
		"{body}"
	);
}

#[tokio::test]
async fn list_is_unsupported() {
	let (provider, _state) = mock().await;
	assert_eq!(
		provider.list("example.org").await,
		Err(ProviderError::Unsupported)
	);
}

#[tokio::test]
async fn srv_upsert_uses_verbatim_value_in_value_element() {
	let (provider, state) = mock().await;
	let srv = DnsRecord {
		name: "_submissions._tcp.example.org".into(),
		kind: RecordKind::Srv,
		value: "0 1 465 mail.example.org.".into(),
		ttl: 3600,
	};
	provider
		.upsert("example.org", srv)
		.await
		.expect("srv upsert");
	let body = state.lock().unwrap().bodies[0].clone();
	assert!(body.contains("<Type>SRV</Type>"), "{body}");
	assert!(
		body.contains("<Value>0 1 465 mail.example.org.</Value>"),
		"{body}"
	);
}

#[tokio::test]
async fn caa_upsert_uses_verbatim_value_in_value_element() {
	let (provider, state) = mock().await;
	let caa = DnsRecord {
		name: "example.org".into(),
		kind: RecordKind::Caa,
		value: "0 issue \"letsencrypt.org\"".into(),
		ttl: 3600,
	};
	provider
		.upsert("example.org", caa)
		.await
		.expect("caa upsert");
	let body = state.lock().unwrap().bodies[0].clone();
	assert!(body.contains("<Type>CAA</Type>"), "{body}");
	assert!(
		body.contains("<Value>0 issue \"letsencrypt.org\"</Value>"),
		"{body}"
	);
}
