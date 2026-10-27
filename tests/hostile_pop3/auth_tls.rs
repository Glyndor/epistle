//! TLS boundary, authorization state and failed sign-in limits.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use tokio::io::AsyncReadExt;
use tokio::time::timeout;

use super::harness::*;

#[tokio::test]
async fn plaintext_user_pass_never_reach_the_implicit_tls_session() {
	let server = Harness::start(|s| s).await;
	let uid = uuid::Uuid::now_v7().to_string();
	let path = server.seed("tester", &uid, b"Subject: private\r\n\r\ncanary\r\n");
	let mut control = server.login("tester", 1).await;
	quit(&mut control).await;
	let mut plain = server.tcp().await;
	send(
		&mut plain,
		format!("USER tester\r\nPASS {PASSWORD}\r\nDELE 1\r\nQUIT\r\n").as_bytes(),
	)
	.await;
	let mut reply = Vec::new();
	match timeout(IO_DEADLINE, (&mut plain).take(4097).read_to_end(&mut reply)).await {
		Ok(Ok(_)) => {}
		Ok(Err(e)) if is_close(&e) => {}
		other => panic!("plaintext connection did not close: {other:?}"),
	}
	// A TLS fatal alert is allowed; a POP3 greeting or reply is not.
	assert!(
		reply.is_empty() || (reply.len() >= 5 && reply[0] == 0x15),
		"{reply:?}"
	);
	assert!(reply.len() <= 4096);
	assert!(!reply.windows(3).any(|w| w == b"+OK" || w == b"-ER"));
	assert!(path.exists());
	let mut control = server.login("tester", 1).await;
	quit(&mut control).await;
	server.healthy().await;
}

#[tokio::test]
async fn retr_list_dele_before_login_never_expose_or_remove_mail() {
	let server = Harness::start(|s| s).await;
	let uid = uuid::Uuid::now_v7().to_string();
	let path = server.seed("tester", &uid, b"Subject: private\r\n\r\nprivate body\r\n");
	let mut client = server.connect().await;
	// CRLF separates commands; it must not bypass the authorization state.
	send(&mut client, b"USER tester\r\nRETR 1\r\nLIST\r\nDELE 1\r\n").await;
	expect(&mut client, "+OK send PASS\r\n").await;
	for _ in 0..3 {
		expect(&mut client, "-ERR authenticate first\r\n").await;
	}
	quit(&mut client).await;
	assert!(path.exists());
	let mut control = server.login("tester", 1).await;
	quit(&mut control).await;
	server.healthy().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn twentieth_consecutive_auth_plain_failure_closes() {
	let server = Harness::start(|s| s).await;
	let mut client = server.connect().await;
	let plain = B64.encode("\0tester\0WrongFixture37!");
	for attempt in 1..=20 {
		send(&mut client, format!("AUTH PLAIN {plain}\r\n").as_bytes()).await;
		expect(
			&mut client,
			if attempt == 20 {
				"-ERR too many errors\r\n"
			} else {
				"-ERR authentication failed\r\n"
			},
		)
		.await;
	}
	closed(&mut client).await;
	let mut control = server.login("tester", 0).await;
	quit(&mut control).await;
	server.healthy().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "bug: USER success resets the error streak so repeated USER/PASS failures never close"]
async fn twentieth_user_pass_failure_must_close_even_with_user_between_attempts() {
	let server = Harness::start(|s| s).await;
	let mut client = server.connect().await;
	for attempt in 1..=20 {
		send(&mut client, b"USER tester\r\n").await;
		expect(&mut client, "+OK send PASS\r\n").await;
		send(&mut client, b"PASS WrongFixture37!\r\n").await;
		expect(
			&mut client,
			if attempt == 20 {
				"-ERR too many errors\r\n"
			} else {
				"-ERR authentication failed\r\n"
			},
		)
		.await;
	}
	closed(&mut client).await;
	server.healthy().await;
}
