//! Socket tests for the real read-only request path. Run outside restricted sandboxes.

use super::*;
use crate::dns::provider::{DnsProvider, ScopedSecret};
use crate::dns::providers::check::Outcome;
use axum::{
	Router,
	extract::State,
	http::{Method, StatusCode, Uri},
	routing::any,
};
use serde_json::json;
use std::sync::{Arc, Mutex};

const ID: &str = "11111111111111111111111111111111";
const EXTRA: &str = "22222222222222222222222222222222";

#[derive(Clone)]
struct Mock {
	verify: Value,
	policies: Value,
	zones: Vec<Value>,
	policy_status: StatusCode,
	calls: Arc<Mutex<Vec<String>>>,
}

fn fixture() -> Mock {
	Mock {
		verify: json!({"id":ID, "status":"active", "expires_on":"2099-01-01T00:00:00Z"}),
		policies: json!({"policies":[{"effect":"allow", "permission_groups":[{"id":"4755a26eedb94da69e1066d98aa820be","name":"DNS Write"}], "resources":{format!("com.cloudflare.api.account.zone.{ID}"):"*"}}]}),
		zones: vec![json!({"id":ID,"name":"example.org"})],
		policy_status: StatusCode::OK,
		calls: Arc::default(),
	}
}

async fn respond(
	State(mock): State<Mock>,
	method: Method,
	uri: Uri,
) -> (StatusCode, axum::Json<Value>) {
	mock.calls
		.lock()
		.unwrap()
		.push(format!("{method} {}", uri.path()));
	if method != Method::GET {
		return (StatusCode::METHOD_NOT_ALLOWED, axum::Json(json!({})));
	}
	let mut status = StatusCode::OK;
	let result = match uri.path() {
		"/user/tokens/verify" => mock.verify,
		"/zones" => {
			return (
				status,
				axum::Json(json!({"success":true,"result":mock.zones,
			"result_info":{"page":1,"total_pages":1,"total_count":mock.zones.len()}})),
			);
		}
		path if path.starts_with("/user/tokens/") => {
			status = mock.policy_status;
			mock.policies
		}
		path if path.ends_with("/dns_records") => json!([]),
		_ => {
			status = StatusCode::NOT_FOUND;
			Value::Null
		}
	};
	(
		status,
		axum::Json(json!({"success":status.is_success(),"result":result})),
	)
}

async fn inspect(mock: Mock) -> (AccessReport, Vec<String>) {
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let address = listener.local_addr().unwrap();
	let calls = mock.calls.clone();
	let server = tokio::spawn(
		axum::serve(
			listener,
			Router::new().fallback(any(respond)).with_state(mock),
		)
		.into_future(),
	);
	let secret = crate::test_fixtures::fresh_secret();
	let provider = CloudflareProvider::new(ScopedSecret::new("example.org", &secret))
		.with_base(HttpsUrl::loopback_http(&format!("http://{address}")).unwrap());
	let report = provider
		.check_access(
			"example.org",
			&[
				"mail.example.org".into(),
				"autoconfig.example.org".into(),
				"mta-sts.example.org".into(),
			],
		)
		.await;
	let json = serde_json::to_string(&report).unwrap();
	assert!(!json.contains(&secret));
	assert!(!json.contains(&secret[..8]));
	server.abort();
	let calls = calls.lock().unwrap().clone();
	assert!(calls.iter().all(|call| call.starts_with("GET ")));
	(report, calls)
}

#[tokio::test]
async fn active_token_with_write_reads_only() {
	let (report, calls) = inspect(fixture()).await;
	assert_eq!(report.token_status.status, Outcome::Verified);
	assert_eq!(report.record_read.status, Outcome::Verified);
	assert_eq!(report.record_write.status, Outcome::Verified);
	assert_eq!(report.zones.status, Outcome::Verified);
	assert_eq!(report.expiry.status, Outcome::Verified);
	assert!(calls.iter().any(|call| call.ends_with("/dns_records")));
}

#[tokio::test]
async fn token_without_write_permission() {
	let mut mock = fixture();
	mock.policies["policies"][0]["permission_groups"][0]["name"] = json!("DNS Read");
	mock.policies["policies"][0]["permission_groups"][0]["id"] =
		json!("82e64a83756745bbbb1c9c2701bf816b");
	let (report, _) = inspect(mock).await;
	assert_eq!(report.record_read.status, Outcome::Verified);
	assert_eq!(report.record_write.status, Outcome::Failure);
}

#[tokio::test]
async fn extra_zone_and_missing_own_names() {
	let mut mock = fixture();
	mock.zones.push(json!({"id":EXTRA, "name":"extra.example"}));
	let (report, _) = inspect(mock).await;
	assert!(report.zones.detail.contains("extra zones: extra.example"));
	assert!(report.scope.detail.contains("broader than needed"));
	let mut mock = fixture();
	mock.zones = vec![json!({"id":EXTRA, "name":"extra.example"})];
	let (report, _) = inspect(mock).await;
	assert_eq!(report.zones.status, Outcome::Failure);
	assert!(report.zones.detail.contains("mail.example.org"));
}

#[tokio::test]
async fn expired_and_nearly_expired_tokens() {
	let mut mock = fixture();
	mock.verify["status"] = json!("expired");
	mock.verify["expires_on"] = json!("2020-01-01T00:00:00Z");
	let (report, _) = inspect(mock).await;
	assert_eq!(report.token_status.status, Outcome::Failure);
	assert_eq!(report.expiry.status, Outcome::Failure);
	assert_eq!(report.record_write.status, Outcome::Failure);
	let mut mock = fixture();
	let soon = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap()
		.as_secs()
		+ 86_400;
	mock.verify["expires_on"] = json!(crate::clock::rfc3339(soon));
	let (report, _) = inspect(mock).await;
	assert!(report.expiry.detail.contains("within seven days"));
}

#[tokio::test]
async fn unavailable_policy_metadata_stays_unknown() {
	let mut mock = fixture();
	mock.policy_status = StatusCode::FORBIDDEN;
	let (report, _) = inspect(mock).await;
	assert_eq!(report.record_read.status, Outcome::Verified);
	assert_eq!(report.record_write.status, Outcome::NotVerifiable);
	assert_eq!(report.scope.status, Outcome::NotVerifiable);
}

#[tokio::test]
async fn network_error_has_a_cause_without_a_credential() {
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let address = listener.local_addr().unwrap();
	drop(listener);
	let secret = crate::test_fixtures::fresh_secret();
	let provider = CloudflareProvider::new(ScopedSecret::new("example.org", &secret))
		.with_base(HttpsUrl::loopback_http(&format!("http://{address}")).unwrap());
	let report = provider.check_access("example.org", &[]).await;
	assert_eq!(report.token_status.status, Outcome::Failure);
	assert!(report.token_status.detail.contains("request failed"));
	assert!(!serde_json::to_string(&report).unwrap().contains(&secret));
}
