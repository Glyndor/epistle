//! Tests for the Route 53 provider: the SigV4 signature against AWS's
//! documented example, timestamp formatting, and the request against a mock.

use super::*;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::State;
use axum::routing::post;

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
struct MockState {
	bodies: Vec<String>,
	auth: Option<String>,
}

type Shared = Arc<Mutex<MockState>>;

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

async fn mock() -> (Route53Provider, Shared) {
	let state: Shared = Arc::new(Mutex::new(MockState::default()));
	let app = Router::new()
		.route("/2013-04-01/hostedzone/{id}/rrset", post(change))
		.with_state(state.clone());
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
	assert!(state.lock().unwrap().bodies[0].contains("<Action>DELETE</Action>"));
}

#[tokio::test]
async fn unsupported_kind_is_rejected() {
	let (provider, _state) = mock().await;
	let mx = DnsRecord {
		name: "example.org".into(),
		kind: RecordKind::Mx,
		value: "10 mail.example.org".into(),
		ttl: 3600,
	};
	assert_eq!(
		provider.upsert("example.org", mx).await,
		Err(ProviderError::Unsupported)
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
