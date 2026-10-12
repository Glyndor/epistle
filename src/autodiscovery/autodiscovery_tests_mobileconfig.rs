//! Tests for the Apple `.mobileconfig` profile served over HTTP.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;

async fn get(uri: &str) -> (StatusCode, Option<String>, String) {
	let router = super::router(
		"mail.example.org".to_string(),
		vec!["Example.org".to_string()],
	);
	let response = router
		.oneshot(Request::get(uri).body(Body::empty()).expect("request"))
		.await
		.expect("response");
	let status = response.status();
	let content_type = response
		.headers()
		.get(header::CONTENT_TYPE)
		.and_then(|value| value.to_str().ok())
		.map(str::to_string);
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("body");
	(
		status,
		content_type,
		String::from_utf8_lossy(&bytes).into_owned(),
	)
}

#[tokio::test]
async fn mobileconfig_serves_profile_for_hosted_address() {
	let (status, content_type, plist) = get("/mobileconfig?email=alice@example.org").await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(
		content_type.as_deref(),
		Some("application/x-apple-aspen-config")
	);
	assert!(plist.contains("<plist version=\"1.0\">"), "{plist}");
	assert!(plist.contains("com.apple.mail.managed"), "{plist}");
	assert!(
		plist.contains("<key>IncomingMailServerHostName</key><string>mail.example.org</string>"),
		"{plist}"
	);
	assert!(
		plist.contains("<key>OutgoingMailServerHostName</key><string>mail.example.org</string>"),
		"{plist}"
	);
	assert!(
		plist.contains("<key>IncomingMailServerUsername</key><string>alice@example.org</string>"),
		"{plist}"
	);
	assert!(
		plist.contains("<key>IncomingMailServerPortNumber</key><integer>993</integer>"),
		"{plist}"
	);
	assert!(
		plist.contains("<key>OutgoingMailServerPortNumber</key><integer>587</integer>"),
		"{plist}"
	);
	// The profile never carries a credential: the user types it on install.
	assert!(!plist.contains("Password</key><string>"), "{plist}");
	assert!(!plist.contains("IncomingPassword"), "{plist}");
	assert!(!plist.contains("OutgoingPassword</key>"), "{plist}");
}

#[tokio::test]
async fn mobileconfig_rejects_foreign_domain() {
	let (status, _, body) = get("/mobileconfig?email=bob@other.example").await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	assert!(body.is_empty(), "{body}");
}

#[tokio::test]
async fn mobileconfig_requires_a_full_address() {
	for uri in [
		"/mobileconfig",
		"/mobileconfig?email=example.org",
		"/mobileconfig?email=@example.org",
		"/mobileconfig?email=a%0Ab@example.org",
	] {
		let (status, _, _) = get(uri).await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}");
	}
}

#[tokio::test]
async fn mobileconfig_matches_domain_case_insensitively() {
	let (status, _, plist) = get("/mobileconfig?email=Alice@EXAMPLE.org").await;
	assert_eq!(status, StatusCode::OK);
	assert!(
		plist.contains("<key>EmailAddress</key><string>Alice@EXAMPLE.org</string>"),
		"{plist}"
	);
}
