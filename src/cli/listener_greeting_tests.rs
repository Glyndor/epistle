//! Tests for the greeting check against local fake listeners.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

use super::{Greeting, expect_greeting, greeting_for};
use crate::config::ListenerKind;

const WAIT: Duration = Duration::from_secs(2);

/// A listener that sends `bytes` to the first client, then keeps the
/// connection open until the client goes away.
async fn banner(bytes: &'static [u8]) -> SocketAddr {
	let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
	let addr = listener.local_addr().expect("addr");
	tokio::spawn(async move {
		while let Ok((mut stream, _)) = listener.accept().await {
			let _ = stream.write_all(bytes).await;
			let mut sink = [0u8; 256];
			tokio::spawn(async move {
				while let Ok(n) = tokio::io::AsyncReadExt::read(&mut stream, &mut sink).await {
					if n == 0 {
						break;
					}
				}
			});
		}
	});
	addr
}

#[tokio::test]
async fn smtp_needs_a_220_banner() {
	let good = banner(b"220 mail.example.org ESMTP ready\r\n").await;
	assert!(expect_greeting(good, Greeting::Smtp, WAIT).await.is_ok());
	let bad = banner(b"554 no service here\r\n").await;
	let error = expect_greeting(bad, Greeting::Smtp, WAIT)
		.await
		.unwrap_err();
	assert_eq!(error, "unexpected greeting: 554 no service here");
}

#[tokio::test]
async fn imap_needs_star_ok() {
	let good = banner(b"* OK IMAP4rev2 ready\r\n").await;
	assert!(expect_greeting(good, Greeting::Imap, WAIT).await.is_ok());
	let bad = banner(b"* BYE shutting down\r\n").await;
	let error = expect_greeting(bad, Greeting::Imap, WAIT)
		.await
		.unwrap_err();
	assert_eq!(error, "unexpected greeting: * BYE shutting down");
}

#[tokio::test]
async fn pop3_needs_plus_ok() {
	let good = banner(b"+OK POP3 ready\r\n").await;
	assert!(expect_greeting(good, Greeting::Pop3, WAIT).await.is_ok());
	let bad = banner(b"-ERR busy\r\n").await;
	let error = expect_greeting(bad, Greeting::Pop3, WAIT)
		.await
		.unwrap_err();
	assert_eq!(error, "unexpected greeting: -ERR busy");
}

#[tokio::test]
async fn managesieve_reads_capabilities_up_to_the_ok_line() {
	let good = banner(
		b"\"IMPLEMENTATION\" \"epistle\"\r\n\"SIEVE\" \"fileinto\"\r\n\"STARTTLS\"\r\nOK \"ManageSieve ready.\"\r\n",
	)
	.await;
	assert!(
		expect_greeting(good, Greeting::ManageSieve, WAIT)
			.await
			.is_ok()
	);
	let bad = banner(b"NO \"not today\"\r\n").await;
	let error = expect_greeting(bad, Greeting::ManageSieve, WAIT)
		.await
		.unwrap_err();
	assert_eq!(error, "unexpected greeting: NO \"not today\"");
}

#[tokio::test]
async fn http_accepts_any_status_line_and_rejects_other_protocols() {
	let unauthorized = banner(b"HTTP/1.1 401 Unauthorized\r\ncontent-length: 0\r\n\r\n").await;
	let detail = expect_greeting(unauthorized, Greeting::Http, WAIT)
		.await
		.expect("an HTTP answer counts");
	assert_eq!(detail, "HTTP/1.1 401 Unauthorized");
	let smtp = banner(b"220 hello\r\n").await;
	let error = expect_greeting(smtp, Greeting::Http, WAIT)
		.await
		.unwrap_err();
	assert_eq!(error, "unexpected greeting: 220 hello");
}

#[tokio::test]
async fn a_tls_listener_only_needs_to_accept_the_connection() {
	let open = banner(b"\x16\x03\x01").await;
	assert!(expect_greeting(open, Greeting::TcpOnly, WAIT).await.is_ok());
	let closed = {
		let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
		listener.local_addr().expect("addr")
	};
	let error = expect_greeting(closed, Greeting::TcpOnly, WAIT)
		.await
		.unwrap_err();
	assert!(error.starts_with("cannot connect"), "{error}");
}

#[tokio::test]
async fn a_listener_that_stays_silent_times_out() {
	let silent = banner(b"").await;
	let began = Instant::now();
	let error = expect_greeting(silent, Greeting::Smtp, Duration::from_millis(300))
		.await
		.unwrap_err();
	assert_eq!(error, "no greeting within 300ms");
	assert!(began.elapsed() < Duration::from_secs(2));
}

#[test]
fn each_listener_kind_maps_to_its_greeting() {
	assert_eq!(greeting_for(ListenerKind::Smtp), Greeting::Smtp);
	assert_eq!(greeting_for(ListenerKind::Submission), Greeting::Smtp);
	assert_eq!(greeting_for(ListenerKind::Submissions), Greeting::TcpOnly);
	assert_eq!(greeting_for(ListenerKind::Imap), Greeting::Imap);
	assert_eq!(greeting_for(ListenerKind::Imaps), Greeting::TcpOnly);
	assert_eq!(greeting_for(ListenerKind::Pop3s), Greeting::TcpOnly);
	assert_eq!(
		greeting_for(ListenerKind::ManageSieve),
		Greeting::ManageSieve
	);
	for kind in [
		ListenerKind::Api,
		ListenerKind::Metrics,
		ListenerKind::Acme,
		ListenerKind::Autoconfig,
		ListenerKind::WebDav,
	] {
		assert_eq!(greeting_for(kind), Greeting::Http, "{kind:?}");
	}
}
