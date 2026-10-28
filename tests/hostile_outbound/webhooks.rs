//! Hostile webhook destinations and HTTP replies.

use std::sync::Arc;

use epistle::metrics::Metrics;
use epistle::webhook::{Webhook, WebhookEvent};

use super::harness::{HttpPeer, bounded, within};

async fn redirect(code: u16, target: &str) {
	let response = format!(
		"HTTP/1.1 {code} Redirect\r\nLocation: {target}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
	);
	let front = HttpPeer::start(response.into_bytes(), false).await;
	let webhook = Webhook::new_allowing_private(&front.url(), Some("fixture-secret".into()))
		.expect("webhook");
	assert_eq!(
		within(webhook.send_test())
			.await
			.expect("redirect response")
			.as_u16(),
		code
	);
	assert_eq!(front.count(), 1);
	let metrics = Arc::new(Metrics::new());
	let webhook = webhook.with_metrics(metrics.clone());
	within(webhook.notify(&WebhookEvent::Test {
		message: "hostile".into(),
	}))
	.await;
	assert_eq!(front.count(), 2);
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

#[tokio::test]
async fn redirects_301_302_303_307_308_never_reach_internal_listener() {
	let internal = HttpPeer::start(b"HTTP/1.1 204 No Content\r\n\r\n".to_vec(), false).await;
	for code in [301, 302, 303, 307, 308] {
		redirect(code, &internal.url()).await;
		assert_eq!(
			internal.count(),
			0,
			"redirect {code} leaked the signed event"
		);
	}
}

#[tokio::test]
async fn redirects_to_metadata_ipv6_private_and_unsupported_schemes_are_not_followed() {
	for target in [
		"http://169.254.169.254/latest/meta-data/",
		"http://[::1]/",
		"http://10.0.0.1/",
		"http://172.16.0.1/",
		"http://192.168.0.1/",
		"http://[::ffff:127.0.0.1]/",
		"file:///etc/passwd",
		"gopher://127.0.0.1/",
	] {
		redirect(307, target).await;
	}
}

#[tokio::test]
async fn self_redirect_returns_once_instead_of_looping() {
	// Relative Location points back to this same listener.
	redirect(307, "/hook").await;
}

#[tokio::test]
async fn advertised_petabyte_body_is_not_buffered_or_awaited() {
	let peer = HttpPeer::start(
		b"HTTP/1.1 200 OK\r\nContent-Length: 1000000000000000\r\n\r\n".to_vec(),
		true,
	)
	.await;
	let hook = Webhook::new_allowing_private(&peer.url(), None).expect("webhook");
	assert_eq!(
		within(hook.send_test()).await.expect("headers suffice"),
		200
	);
	assert_eq!(peer.count(), 1);
}

#[tokio::test]
async fn infinite_chunked_body_is_not_read() {
	let peer = HttpPeer::start(
		b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n".to_vec(),
		true,
	)
	.await;
	let hook = Webhook::new_allowing_private(&peer.url(), None).expect("webhook");
	assert_eq!(
		within(hook.send_test())
			.await
			.expect("body is not consumed"),
		200
	);
	assert_eq!(peer.count(), 1);
}

#[tokio::test]
async fn megabyte_response_header_is_rejected() {
	let mut response = b"HTTP/1.1 200 OK\r\nX-Padding: ".to_vec();
	response.extend(std::iter::repeat_n(b'x', 1 << 20));
	response.extend_from_slice(b"\r\nContent-Length: 0\r\n\r\n");
	let peer = HttpPeer::start(response, false).await;
	let hook = Webhook::new_allowing_private(&peer.url(), None).expect("webhook");
	let error = within(hook.send_test())
		.await
		.expect_err("HTTP header limit");
	assert!(
		!error.is_timeout(),
		"header cap must reject before the delivery timeout"
	);
	assert_eq!(peer.count(), 1);
}

#[tokio::test]
async fn silent_receiver_hits_production_fifteen_second_timeout() {
	let peer = HttpPeer::start(Vec::new(), true).await;
	let hook = Webhook::new_allowing_private(&peer.url(), None).expect("webhook");
	let started = std::time::Instant::now();
	let error = within(hook.send_test()).await.expect_err("silent receiver");
	assert!(error.is_timeout(), "{error}");
	assert!(started.elapsed() >= std::time::Duration::from_secs(14));
	assert_eq!(peer.count(), 1);
}

#[tokio::test]
async fn file_and_gopher_initial_urls_fail_before_transport() {
	for url in ["file:///etc/passwd", "gopher://127.0.0.1:9/_test"] {
		let hook = Webhook::new(url, None).expect("client construction");
		let error = within(hook.send_test())
			.await
			.expect_err("unsupported scheme");
		assert!(error.is_builder(), "{error}");
	}
}

// No request to metadata or private networks is made, even with --ignored.
// These expectations require a construction-time destination policy.
macro_rules! private_url {
	($name:ident, $url:literal) => {
		#[test]
		fn $name() {
			bounded(|| {
				assert!(
					Webhook::new($url, None).is_err(),
					"private URL was accepted"
				);
			});
		}
	};
}

private_url!(initial_ipv4_loopback_is_refused, "http://127.0.0.1/hook");
private_url!(initial_ipv6_loopback_is_refused, "http://[::1]/hook");
private_url!(
	initial_metadata_is_refused,
	"http://169.254.169.254/latest/meta-data/"
);
private_url!(initial_ten_network_is_refused, "http://10.0.0.1/hook");
private_url!(initial_172_network_is_refused, "http://172.16.0.1/hook");
private_url!(initial_192_network_is_refused, "http://192.168.0.1/hook");
private_url!(
	initial_mapped_loopback_is_refused,
	"http://[::ffff:127.0.0.1]/hook"
);
private_url!(initial_nat64_is_refused, "http://[64:ff9b::a00:1]/hook");
private_url!(
	initial_nat64_local_use_prefix_is_refused,
	"http://[64:ff9b:1::a00:1]/hook"
);
private_url!(
	initial_six_to_four_is_refused,
	"http://[2002:a00:1::1]/hook"
);
private_url!(
	initial_teredo_is_refused,
	"http://[2001::1234:5678:9abc]/hook"
);
private_url!(initial_decimal_ip_is_refused, "http://2130706433/hook");
private_url!(initial_octal_ip_is_refused, "http://0177.0.0.1/hook");
private_url!(initial_hex_ip_is_refused, "http://0x7f000001/hook");
private_url!(
	initial_userinfo_loopback_is_refused,
	"http://a@127.0.0.1/hook"
);

#[tokio::test]
async fn localhost_resolving_to_loopback_cannot_receive_a_webhook() {
	let peer = HttpPeer::start(b"HTTP/1.1 204 No Content\r\n\r\n".to_vec(), false).await;
	let url = format!("http://localhost:{}/hook", peer.addr.port());
	let rejected = match Webhook::new(&url, None) {
		Err(_) => true,
		Ok(hook) => within(hook.send_test()).await.is_err(),
	};
	assert!(rejected, "resolved loopback destination was accepted");
	assert_eq!(peer.count(), 0, "private endpoint received the event");
}
