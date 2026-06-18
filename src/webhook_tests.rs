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
		recipient: "x@y".into(),
		reason: "boom".into(),
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
		recipient: "x@y".into(),
		reason: "boom".into(),
	})
	.await;
	assert!(
		metrics.render().contains("mail_webhook_failed_total 1\n"),
		"{}",
		metrics.render()
	);
}
