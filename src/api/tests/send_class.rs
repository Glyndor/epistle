//! The class of mail `POST /api/v1/send` submits.

use std::sync::Arc;

use axum::http::StatusCode;
use serde_json::{Value, json};

use super::base::{TOKEN, request_with_body, test_state};
use super::router;
use super::state::{ApiState, MatchedAuth};
use crate::evidence::MailClass;
use crate::evidence::bindings::{BindingSet, api_key_key_of_token, update};
use crate::evidence::service::EvidenceService;
use crate::storage::{FsSpool, MessageCrypto, SplitDelivery};

pub(in super::super) fn state(dir: &std::path::Path) -> (ApiState, Arc<EvidenceService>) {
	let directory =
		crate::directory_store::DirectoryHandle::new(crate::smtp::directory::Directory::new(
			["example.org".to_string()],
			[("alice@example.org".to_string(), "alice".to_string())],
		));
	let service = Arc::new(
		EvidenceService::open(dir, Vec::new(), MessageCrypto::disabled()).expect("evidence"),
	);
	// As after the server's first clean verification.
	service.set_gate(None);
	let split = SplitDelivery::new(dir, directory)
		.expect("sink")
		.with_evidence(Arc::clone(&service));
	let bindings = Arc::new(BindingSet::open(dir).expect("bindings"));
	let state = test_state(dir, 0)
		.with_outbound(Arc::new(split))
		.with_class_bindings(bindings);
	(state, service)
}

pub(in super::super) async fn send(app: &axum::Router, extra: Value) -> (StatusCode, Value) {
	let mut body = json!({"from": "alice@example.org", "to": ["bob@elsewhere.example"], "subject": "s", "text": "hi"});
	for (key, value) in extra.as_object().expect("object") {
		body[key] = value.clone();
	}
	request_with_body(
		app,
		"POST",
		"/api/v1/send",
		Some(TOKEN.as_str()),
		Some(body),
	)
	.await
}

pub(in super::super) fn sent_count(dir: &std::path::Path) -> usize {
	std::fs::read_dir(dir.join("accounts/alice/folders/Sent/new"))
		.map(|entries| {
			entries
				.flatten()
				.filter(|entry| entry.path().extension().is_some_and(|ext| ext == "eml"))
				.count()
		})
		.unwrap_or(0)
}

#[tokio::test]
async fn transactional_mail_is_not_copied_to_sent_and_keeps_evidence() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts/alice")).expect("mkdir");
	let (state, _) = state(dir.path());
	let app = router(state);
	let (status, body) = send(&app, json!({"class": "transactional"})).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["class"], "transactional");
	assert_eq!(
		sent_count(dir.path()),
		0,
		"transactional mail was copied to Sent"
	);
	let spool = FsSpool::open(dir.path()).expect("spool");
	let id = uuid::Uuid::parse_str(body["queued"].as_str().expect("id")).expect("uuid");
	let entry = spool.load(id).expect("queued");
	assert_eq!(entry.envelope.class, MailClass::Transactional);
	assert!(entry.envelope.evidence, "no evidence was recorded");
	let (_, personal) = send(&app, json!({})).await;
	assert_eq!(personal["class"], "personal");
	assert_eq!(
		sent_count(dir.path()),
		1,
		"personal mail keeps its Sent copy"
	);
}

#[tokio::test]
async fn marketing_without_one_click_unsubscribe_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (state, _) = state(dir.path());
	let app = router(state);
	let (status, body) = send(&app, json!({"class": "marketing"})).await;
	assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
	assert_eq!(body["error"]["code"], "marketing_refused");
	let (status, body) = send(
		&app,
		json!({"class": "marketing", "list_unsubscribe": ["https://example.org/u?t=1"], "list_unsubscribe_post": true}),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let id = uuid::Uuid::parse_str(body["queued"].as_str().expect("id")).expect("uuid");
	let queued = FsSpool::open(dir.path())
		.expect("spool")
		.load(id)
		.expect("queued");
	let text = String::from_utf8_lossy(&queued.data).to_string();
	assert!(text.contains("\r\nPrecedence: bulk\r\n") || text.starts_with("Precedence: bulk\r\n"));
}

#[tokio::test]
async fn an_unknown_class_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (state, _) = state(dir.path());
	let (status, body) = send(&router(state), json!({"class": "urgent"})).await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

#[tokio::test]
async fn the_account_default_applies_and_a_held_gate_answers_503() {
	let dir = tempfile::tempdir().expect("tempdir");
	update(dir.path(), |bindings| {
		bindings
			.accounts
			.insert("alice".into(), MailClass::Transactional);
	})
	.expect("bind");
	let (state, service) = state(dir.path());
	let app = router(state);
	let (_, body) = send(&app, json!({})).await;
	assert_eq!(body["class"], "transactional");
	service.set_gate(Some("broken".into()));
	let (status, body) = send(&app, json!({})).await;
	assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
	assert_eq!(body["error"]["code"], "evidence_unavailable");
	// The account default is a floor: asking for personal does not skip it.
	let (status, body) = send(&app, json!({"class": "personal"})).await;
	assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
}

#[test]
fn the_class_bound_to_an_api_key_is_found_by_its_token() {
	let dir = tempfile::tempdir().expect("tempdir");
	let token = crate::test_fixtures::fresh_secret();
	update(dir.path(), |bindings| {
		bindings
			.credentials
			.insert(api_key_key_of_token(&token), MailClass::Transactional);
	})
	.expect("bind");
	let (state, _) = state(dir.path());
	let key = MatchedAuth {
		token: Some(token),
		client_ip: None,
		configured: false,
	};
	assert_eq!(
		state.class_sources(Some(&key), "alice", None).granted(),
		MailClass::Transactional
	);
	let explicit = state.class_sources(Some(&key), "alice", Some(MailClass::Personal));
	assert_eq!(
		explicit.granted(),
		MailClass::Transactional,
		"the key's class is a floor for the request"
	);
	let configured = MatchedAuth {
		configured: true,
		..key
	};
	assert_eq!(
		state
			.class_sources(Some(&configured), "alice", None)
			.granted(),
		MailClass::Personal
	);
}

async fn jmap_submit(dir: &std::path::Path, app: &axum::Router, class: Option<&str>) -> Value {
	let inbox = dir.join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	let email = uuid::Uuid::now_v7();
	std::fs::write(
		inbox.join(format!("{email}.eml")),
		"From: alice@example.org\r\nTo: bob@elsewhere.example\r\nEpistle-Class: transactional\r\nSubject: Drafted\r\n\r\nbody\r\n",
	)
	.expect("write draft");
	let mut create = json!({
		"emailId": email.to_string(),
		"envelope": {"mailFrom": {"email": "alice@example.org"}, "rcptTo": [{"email": "bob@elsewhere.example"}]},
	});
	if let Some(class) = class {
		create["epistle:class"] = json!(class);
	}
	let req = json!({
		"using": ["urn:ietf:params:jmap:submission"],
		"methodCalls": [["EmailSubmission/set", {"accountId": "alice", "create": {"s1": create}}, "c1"]],
	});
	let (status, body) =
		request_with_body(app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	body["methodResponses"][0][1].clone()
}

#[tokio::test]
async fn jmap_takes_the_class_from_its_extension_property_not_the_message() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (state, _) = state(dir.path());
	let app = router(state);
	let response = jmap_submit(dir.path(), &app, None).await;
	let id = response["created"]["s1"]["id"]
		.as_str()
		.expect("created")
		.to_string();
	let spool = FsSpool::open(dir.path()).expect("spool");
	let entry = spool
		.load(uuid::Uuid::parse_str(&id).expect("uuid"))
		.expect("queued");
	assert_eq!(
		entry.envelope.class,
		MailClass::Personal,
		"the message's header raised the class"
	);
	assert!(!String::from_utf8_lossy(&entry.data).contains("Epistle-Class"));
	let response = jmap_submit(dir.path(), &app, Some("transactional")).await;
	let id = response["created"]["s1"]["id"]
		.as_str()
		.expect("created")
		.to_string();
	let entry = spool
		.load(uuid::Uuid::parse_str(&id).expect("uuid"))
		.expect("queued");
	assert_eq!(entry.envelope.class, MailClass::Transactional);
	let response = jmap_submit(dir.path(), &app, Some("urgent")).await;
	assert_eq!(response["notCreated"]["s1"]["type"], "invalidProperties");
}
