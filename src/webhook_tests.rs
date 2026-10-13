//! Webhook poster tests: payload shape, delivery, and HMAC signing.

use super::*;
use std::sync::{Arc, Mutex};

#[test]
fn message_received_serializes_with_event_tag() {
	let event = WebhookEvent::MessageReceived {
		account: "alice".into(),
		from: "bob@example.net".into(),
		subject: Some("hi".into()),
		message_id: Some("<m1@x>".into()),
	};
	let json = serde_json::to_string(&event).expect("serialize");
	assert!(json.contains("\"event\":\"message_received\""), "{json}");
	assert!(json.contains("\"message_id\":\"<m1@x>\""), "{json}");
	assert!(json.contains("\"account\":\"alice\""), "{json}");
	assert!(json.contains("\"subject\":\"hi\""), "{json}");
}

#[test]
fn signature_is_stable_hmac_sha256() {
	let a = sign("secret", b"body");
	assert!(a.starts_with("sha256="));
	assert_eq!(a, sign("secret", b"body"));
	assert_ne!(a, sign("other", b"body"));
}

#[test]
fn metric_alert_serializes_with_event_tag() {
	let event = WebhookEvent::MetricAlert {
		name: "bounce-storm".into(),
		metric: "bounced".into(),
		value: 73,
		threshold: 50,
		window_secs: 300,
	};
	let json = serde_json::to_string(&event).expect("serialize");
	assert!(json.contains("\"event\":\"metric_alert\""), "{json}");
	assert!(json.contains("\"name\":\"bounce-storm\""), "{json}");
	assert!(json.contains("\"metric\":\"bounced\""), "{json}");
	assert!(json.contains("\"value\":73"), "{json}");
	assert!(json.contains("\"threshold\":50"), "{json}");
	assert!(json.contains("\"window_secs\":300"), "{json}");
}

/// Captured request: (body, signature header).
type Captured = Arc<Mutex<Option<(String, Option<String>)>>>;

async fn mock_server(captured: Captured) -> String {
	use axum::extract::State;
	use axum::http::HeaderMap;
	async fn handler(
		State(captured): State<Captured>,
		headers: HeaderMap,
		body: String,
	) -> &'static str {
		let sig = headers
			.get("x-webhook-signature")
			.and_then(|v| v.to_str().ok())
			.map(str::to_string);
		*captured.lock().expect("lock") = Some((body, sig));
		"ok"
	}
	let app = axum::Router::new()
		.route("/hook", axum::routing::post(handler))
		.with_state(captured);
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
		.await
		.expect("bind");
	let addr = listener.local_addr().expect("addr");
	tokio::spawn(async move {
		axum::serve(listener, app).await.expect("serve");
	});
	format!("http://{addr}/hook")
}

#[tokio::test]
async fn delivers_signed_payload() {
	let captured: Captured = Arc::new(Mutex::new(None));
	let url = mock_server(captured.clone()).await;
	let webhook = Webhook::new(&url, Some("topsecret".into())).expect("webhook");

	let event = WebhookEvent::MessageReceived {
		account: "alice".into(),
		from: "bob@example.net".into(),
		subject: None,
		message_id: None,
	};
	webhook.notify(&event).await;

	let (body, sig) = captured.lock().expect("lock").clone().expect("a request");
	assert!(body.contains("message_received"), "{body}");
	// The signature matches an HMAC of exactly the received body.
	assert_eq!(
		sig.as_deref(),
		Some(sign("topsecret", body.as_bytes()).as_str())
	);
}

#[tokio::test]
async fn unsigned_delivery_omits_signature_header() {
	let captured: Captured = Arc::new(Mutex::new(None));
	let url = mock_server(captured.clone()).await;
	let webhook = Webhook::new(&url, None).expect("webhook");
	webhook
		.notify(&WebhookEvent::MessageReceived {
			account: "a".into(),
			from: "b@c".into(),
			subject: None,
			message_id: None,
		})
		.await;
	let (_, sig) = captured.lock().expect("lock").clone().expect("request");
	assert!(sig.is_none(), "unsigned webhook must not send a signature");
}

#[tokio::test]
async fn unreachable_endpoint_fails_open() {
	// Port 1 refuses; notify must return without panicking.
	let webhook = Webhook::new("http://127.0.0.1:1/hook", None).expect("webhook");
	webhook
		.notify(&WebhookEvent::MessageReceived {
			account: "a".into(),
			from: "b@c".into(),
			subject: None,
			message_id: None,
		})
		.await;
}

#[tokio::test]
async fn records_delivery_metrics() {
	use std::sync::Arc;
	let captured: Captured = Arc::new(std::sync::Mutex::new(None));
	let url = mock_server(captured).await;
	let metrics = Arc::new(crate::metrics::Metrics::new());

	// A successful delivery bumps webhook_sent.
	let ok = Webhook::new(&url, None)
		.expect("wh")
		.with_metrics(metrics.clone());
	ok.notify(&WebhookEvent::DeliveryFailed {
		spool_id: None,
		recipient: "x@y".into(),
		reason: "boom".into(),
		class: "other".into(),
		remote: None,
		extra: BTreeMap::new(),
	})
	.await;
	assert!(
		metrics.render().contains("mail_webhook_sent_total 1\n"),
		"{}",
		metrics.render()
	);

	// An unreachable endpoint bumps webhook_failed.
	let bad = Webhook::new("http://127.0.0.1:1/hook", None)
		.expect("wh")
		.with_metrics(metrics.clone());
	bad.notify(&WebhookEvent::DeliveryFailed {
		spool_id: None,
		recipient: "x@y".into(),
		reason: "boom".into(),
		class: "other".into(),
		remote: None,
		extra: BTreeMap::new(),
	})
	.await;
	assert!(
		metrics.render().contains("mail_webhook_failed_total 1\n"),
		"{}",
		metrics.render()
	);
}

#[test]
fn test_event_has_the_documented_shape() {
	let event = WebhookEvent::Test {
		message: TEST_MESSAGE.into(),
	};
	assert_eq!(
		serde_json::to_string(&event).expect("serialize"),
		"{\"event\":\"test\",\"message\":\"epistle webhook test: connectivity check, no mail activity\"}"
	);
}

#[tokio::test]
async fn send_test_posts_a_signed_test_event_and_returns_the_status() {
	let captured: Captured = Arc::new(Mutex::new(None));
	let url = mock_server(captured.clone()).await;
	let webhook = Webhook::new(&url, Some("topsecret".into())).expect("webhook");
	let status = webhook.send_test().await.expect("reachable endpoint");
	assert_eq!(status.as_u16(), 200);
	let (body, sig) = captured.lock().expect("lock").clone().expect("a request");
	assert_eq!(
		body,
		"{\"event\":\"test\",\"message\":\"epistle webhook test: connectivity check, no mail activity\"}"
	);
	assert_eq!(
		sig.as_deref(),
		Some(sign("topsecret", body.as_bytes()).as_str()),
		"the test event must be signed like any other"
	);
}

#[tokio::test]
async fn send_test_reports_an_error_status_and_an_unreachable_endpoint() {
	let captured: Captured = Arc::new(Mutex::new(None));
	let url = mock_server(captured).await;
	let missing = Webhook::new(&format!("{url}-missing"), None).expect("webhook");
	assert_eq!(missing.send_test().await.expect("answered").as_u16(), 404);
	let down = Webhook::new("http://127.0.0.1:1/hook", None).expect("webhook");
	assert!(
		down.send_test().await.is_err(),
		"a refused connection is an error"
	);
}

fn extra() -> BTreeMap<String, String> {
	let mut map = BTreeMap::new();
	map.insert("trace_id".into(), "abc-123".into());
	map
}

#[test]
fn delivered_serializes_with_event_tag_and_stable_field_order() {
	let id = Uuid::nil();
	let event = WebhookEvent::Delivered {
		spool_id: id,
		recipient: "bob@remote.example".into(),
		message_id: Some("<m1@elsewhere.example>".into()),
		remote: Some("mx.remote.example".into()),
		extra: extra(),
	};
	let json: serde_json::Value = serde_json::from_str(
		&serde_json::to_string(&event).expect("serialize"),
	)
	.expect("value");
	assert_eq!(json["event"], "delivered");
	assert_eq!(json["spool_id"], id.to_string());
	assert_eq!(json["recipient"], "bob@remote.example");
	assert_eq!(json["message_id"], "<m1@elsewhere.example>");
	assert_eq!(json["remote"], "mx.remote.example");
	assert_eq!(json["extra"]["trace_id"], "abc-123");
}

#[test]
fn delayed_serializes_with_event_tag_and_carries_attempt_and_reason() {
	let id = Uuid::nil();
	let event = WebhookEvent::Delayed {
		spool_id: id,
		recipient: "bob@remote.example".into(),
		reason: "450 4.2.1 mailbox busy, try later".into(),
		remote: Some("mx.remote.example".into()),
		attempt: 1,
		extra: BTreeMap::new(),
	};
	let json: serde_json::Value = serde_json::from_str(
		&serde_json::to_string(&event).expect("serialize"),
	)
	.expect("value");
	assert_eq!(json["event"], "delayed");
	assert_eq!(json["spool_id"], id.to_string());
	assert_eq!(json["recipient"], "bob@remote.example");
	assert_eq!(json["reason"], "450 4.2.1 mailbox busy, try later");
	assert_eq!(json["remote"], "mx.remote.example");
	assert_eq!(json["attempt"], 1);
	assert!(
		json.get("extra").is_none(),
		"empty extra must not appear: {}",
		json
	);
}

#[test]
fn suppressed_serializes_with_event_tag() {
	let id = Uuid::nil();
	let event = WebhookEvent::Suppressed {
		spool_id: id,
		recipient: "bob@remote.example".into(),
		extra: BTreeMap::new(),
	};
	let json: serde_json::Value = serde_json::from_str(
		&serde_json::to_string(&event).expect("serialize"),
	)
	.expect("value");
	assert_eq!(json["event"], "suppressed");
	assert_eq!(json["spool_id"], id.to_string());
	assert_eq!(json["recipient"], "bob@remote.example");
	assert!(json.get("extra").is_none());
}

#[test]
fn canceled_serializes_with_event_tag() {
	let id = Uuid::nil();
	let event = WebhookEvent::Canceled {
		spool_id: id,
		recipient: "bob@remote.example".into(),
		extra: BTreeMap::new(),
	};
	let json: serde_json::Value = serde_json::from_str(
		&serde_json::to_string(&event).expect("serialize"),
	)
	.expect("value");
	assert_eq!(json["event"], "canceled");
	assert_eq!(json["spool_id"], id.to_string());
	assert_eq!(json["recipient"], "bob@remote.example");
	assert!(json.get("extra").is_none());
}

#[test]
fn delivery_failed_with_a_pre_addition_body_still_deserialises() {
	// Bodies written before `spool_id` and `extra` were added did not
	// carry those fields. A receiver that runs an older webhook handler
	// must keep accepting them; the deserialiser makes both fields
	// optional with `serde(default)`.
	let body = serde_json::json!({
		"event": "delivery_failed",
		"recipient": "bob@remote.example",
		"reason": "550 5.1.1 user unknown",
		"class": "invalid_address",
		"remote": "mx.remote.example",
	})
	.to_string();
	let event: WebhookEvent = serde_json::from_str(&body).expect("backward compat");
	match event {
		WebhookEvent::DeliveryFailed {
			spool_id,
			recipient,
			reason,
			class,
			remote,
			extra,
		} => {
			assert!(spool_id.is_none(), "no spool id in the old body");
			assert_eq!(recipient, "bob@remote.example");
			assert_eq!(reason, "550 5.1.1 user unknown");
			assert_eq!(class, "invalid_address");
			assert_eq!(remote.as_deref(), Some("mx.remote.example"));
			assert!(extra.is_empty(), "no extra map in the old body");
		}
		other => panic!("expected DeliveryFailed, got {other:?}"),
	}
}
