//! Tests for the autodiscovery documents and HTTP handlers.

use super::*;

async fn body(response: Response) -> (StatusCode, String) {
	let status = response.status();
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("body");
	(status, String::from_utf8_lossy(&bytes).into_owned())
}

fn state() -> Discovery {
	Discovery {
		hostname: "mail.example.org".to_string(),
		domains: vec!["example.org".to_string()].into(),
	}
}

#[test]
fn builders_emit_expected_documents() {
	let ac = autoconfig("example.org", "mail.example.org");
	assert!(ac.contains("<clientConfig version=\"1.1\">"), "{ac}");
	assert!(ac.contains("<emailProvider id=\"example.org\">"), "{ac}");
	let ad = autodiscover("mail.example.org");
	assert!(ad.contains("<Type>IMAP</Type>"), "{ad}");
	assert!(ad.contains("<Server>mail.example.org</Server>"), "{ad}");
}

#[test]
fn domain_of_extracts_and_lowercases() {
	assert_eq!(
		domain_of("Alice@Example.ORG").as_deref(),
		Some("example.org")
	);
	assert_eq!(domain_of("no-at-sign"), None);
	assert_eq!(domain_of("trailing@"), None);
}

#[test]
fn escape_handles_special_characters() {
	assert_eq!(escape("a<b&c\""), "a&lt;b&amp;c&quot;");
}

#[tokio::test]
async fn autoconfig_handler_serves_hosted_domain() {
	let params = HashMap::from([("emailaddress".to_string(), "alice@example.org".to_string())]);
	let (status, text) = body(autoconfig_handler(State(state()), Query(params)).await).await;
	assert_eq!(status, StatusCode::OK);
	assert!(
		text.contains("<emailProvider id=\"example.org\">"),
		"{text}"
	);
}

#[tokio::test]
async fn autoconfig_handler_rejects_unknown_domain() {
	let params = HashMap::from([("emailaddress".to_string(), "bob@other.example".to_string())]);
	let (status, _) = body(autoconfig_handler(State(state()), Query(params)).await).await;
	assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn autoconfig_handler_requires_emailaddress() {
	let (status, _) = body(autoconfig_handler(State(state()), Query(HashMap::new())).await).await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn autodiscover_handler_serves_document() {
	let (status, text) = body(autodiscover_handler(State(state())).await).await;
	assert_eq!(status, StatusCode::OK);
	assert!(
		text.contains("schemas.microsoft.com/exchange/autodiscover"),
		"{text}"
	);
}

#[test]
fn v2_builder_covers_protocols_and_redirect() {
	let imap = autodiscover_v2("mail.example.org", "Imap").expect("imap");
	assert!(imap.contains("\"Protocol\":\"IMAP\""), "{imap}");
	assert!(imap.contains("\"Port\":993"), "{imap}");
	assert!(imap.contains("\"SSL\":true"), "{imap}");
	let smtp = autodiscover_v2("mail.example.org", "smtp").expect("smtp");
	assert!(smtp.contains("\"Port\":587"), "{smtp}");
	assert!(smtp.contains("\"SSL\":false"), "{smtp}");
	let pop = autodiscover_v2("mail.example.org", "POP").expect("pop");
	assert!(pop.contains("\"Port\":995"), "{pop}");
	let v1 = autodiscover_v2("mail.example.org", "Autodiscoverv1").expect("v1");
	assert!(v1.contains("/autodiscover/autodiscover.xml"), "{v1}");
	assert!(autodiscover_v2("mail.example.org", "ActiveSync").is_none());
}

#[tokio::test]
async fn v2_handler_serves_json_for_hosted_email() {
	let params = HashMap::from([
		("Email".to_string(), "alice@example.org".to_string()),
		("Protocol".to_string(), "Imap".to_string()),
	]);
	let (status, text) = body(autodiscover_v2_handler(State(state()), Query(params)).await).await;
	assert_eq!(status, StatusCode::OK);
	assert!(text.contains("\"Protocol\":\"IMAP\""), "{text}");
}

#[tokio::test]
async fn v2_handler_requires_protocol() {
	let params = HashMap::from([("Email".to_string(), "alice@example.org".to_string())]);
	let (status, _) = body(autodiscover_v2_handler(State(state()), Query(params)).await).await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn v2_handler_rejects_unknown_domain_and_protocol() {
	let params = HashMap::from([
		("Email".to_string(), "bob@other.example".to_string()),
		("Protocol".to_string(), "Imap".to_string()),
	]);
	let (status, _) = body(autodiscover_v2_handler(State(state()), Query(params)).await).await;
	assert_eq!(status, StatusCode::NOT_FOUND);

	let params = HashMap::from([("Protocol".to_string(), "ActiveSync".to_string())]);
	let (status, _) = body(autodiscover_v2_handler(State(state()), Query(params)).await).await;
	assert_eq!(status, StatusCode::NOT_FOUND);
}
