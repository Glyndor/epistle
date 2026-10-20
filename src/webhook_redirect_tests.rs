//! The webhook endpoint is operator-chosen, but whatever answers there must not
//! be able to send the signed POST on to another address.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

/// A server on a second port that counts what reaches it, and a first one that
/// answers every POST with a 307 pointing at the second. Returns the first
/// one's URL and the counter.
async fn redirecting_endpoint() -> (String, Arc<AtomicUsize>) {
	let hits = Arc::new(AtomicUsize::new(0));
	let counter = Arc::clone(&hits);
	let internal = axum::Router::new().route(
		"/internal",
		axum::routing::post(move || {
			let counter = Arc::clone(&counter);
			async move {
				counter.fetch_add(1, Ordering::SeqCst);
				"reached"
			}
		}),
	);
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
		.await
		.expect("bind");
	let internal_addr = listener.local_addr().expect("addr");
	tokio::spawn(async move {
		axum::serve(listener, internal).await.expect("serve");
	});
	let target = format!("http://{internal_addr}/internal");
	let front = axum::Router::new().route(
		"/hook",
		axum::routing::post(move || {
			let target = target.clone();
			async move {
				(
					axum::http::StatusCode::TEMPORARY_REDIRECT,
					[(axum::http::header::LOCATION, target)],
				)
			}
		}),
	);
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
		.await
		.expect("bind");
	let addr = listener.local_addr().expect("addr");
	tokio::spawn(async move {
		axum::serve(listener, front).await.expect("serve");
	});
	(format!("http://{addr}/hook"), hits)
}

#[tokio::test]
async fn a_redirect_is_not_followed_by_the_test_event() {
	let (url, hits) = redirecting_endpoint().await;
	let webhook = Webhook::new(&url, Some("topsecret".into())).expect("webhook");
	let status = webhook
		.send_test()
		.await
		.expect("the redirect is an answer");
	assert_eq!(status, reqwest::StatusCode::TEMPORARY_REDIRECT);
	assert_eq!(hits.load(Ordering::SeqCst), 0, "nothing reached the target");
}

#[tokio::test]
async fn a_redirect_is_a_failed_delivery_and_is_not_followed() {
	let (url, hits) = redirecting_endpoint().await;
	let metrics = Arc::new(crate::metrics::Metrics::new());
	let webhook = Webhook::new(&url, Some("topsecret".into()))
		.expect("webhook")
		.with_metrics(metrics.clone());
	webhook
		.notify(&WebhookEvent::Test {
			message: TEST_MESSAGE.into(),
		})
		.await;
	assert_eq!(hits.load(Ordering::SeqCst), 0);
	let rendered = metrics.render();
	assert!(
		rendered.contains("mail_webhook_failed_total 1\n"),
		"{rendered}"
	);
	assert!(
		rendered.contains("mail_webhook_sent_total 0\n"),
		"{rendered}"
	);
}
