//! Authentication state guards and the plaintext-to-TLS boundary.

use super::harness::*;

#[tokio::test]
async fn select_fetch_and_append_before_login_never_expose_or_store_mail() {
	let server = Harness::start(|s| s).await;
	let inbox = server.data.path().join("accounts/tester/new");
	std::fs::create_dir_all(&inbox).expect("seed inbox");
	std::fs::write(
		inbox.join(format!("{}.eml", uuid::Uuid::now_v7())),
		b"Subject: private-canary\r\n\r\nprivate-canary-body\r\n",
	)
	.expect("seed private message");
	// Test both plaintext and encrypted-but-unauthenticated connections.
	let mut plain = server.connect().await;
	preauth_commands(&mut plain).await;
	logout(&mut plain).await;
	let mut client = server.encrypted().await;
	preauth_commands(&mut client).await;
	logout(&mut client).await;
	// Prove that the denied commands were aimed at a populated mailbox.
	let mut control = server.authenticated().await;
	assert!(select_inbox(&mut control).await.contains("* 1 EXISTS\r\n"));
	send(&mut control, b"F FETCH 1 (BODY.PEEK[TEXT])\r\n").await;
	let mut response = String::new();
	for _ in 0..10 {
		let reply = line(&mut control)
			.await
			.expect("FETCH reply")
			.expect("open");
		let done = reply == "F OK FETCH completed\r\n";
		response.push_str(&reply);
		if done {
			break;
		}
	}
	assert!(response.ends_with("F OK FETCH completed\r\n"));
	assert!(response.contains("private-canary-body\r\n"));
	logout(&mut control).await;
	server.healthy().await;
}

async fn preauth_commands<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(client: &mut S) {
	for (command, reply) in [
		("A1 SELECT INBOX\r\n", "A1 NO not authenticated\r\n"),
		(
			"A2 FETCH 1:* (BODY[])\r\n",
			"A2 BAD no mailbox selected\r\n",
		),
		("A3 APPEND INBOX {4}\r\n", "A3 NO not authenticated\r\n"),
		(
			"A4 APPEND INBOX {4+}\r\nEVIL\r\n",
			"A4 NO not authenticated\r\n",
		),
	] {
		send(client, command.as_bytes()).await;
		expect(client, reply).await;
	}
	noop(client).await;
}

#[tokio::test]
async fn logindisabled_refuses_valid_cleartext_credentials() {
	let server = Harness::start(|s| s).await;
	let mut client = server.connect().await;
	send(&mut client, b"C CAPABILITY\r\n").await;
	let caps = line(&mut client)
		.await
		.expect("capabilities")
		.expect("open");
	assert!(caps.starts_with("* CAPABILITY "));
	assert!(caps.split_ascii_whitespace().any(|c| c == "LOGINDISABLED"));
	expect(&mut client, "C OK CAPABILITY completed\r\n").await;
	send(
		&mut client,
		format!("A1 LOGIN tester {PASSWORD}\r\n").as_bytes(),
	)
	.await;
	expect(&mut client, "A1 NO [PRIVACYREQUIRED] STARTTLS first\r\n").await;
	send(&mut client, b"A2 SELECT INBOX\r\n").await;
	expect(&mut client, "A2 NO not authenticated\r\n").await;
	logout(&mut client).await;
	let mut control = server.authenticated().await;
	logout(&mut control).await;
	server.healthy().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn third_failed_login_gets_bye_no_and_close() {
	let server = Harness::start(|s| s).await;
	let mut client = server.encrypted().await;
	for attempt in 1..=3 {
		send(
			&mut client,
			format!("A{attempt} LOGIN tester WrongFixture37!\r\n").as_bytes(),
		)
		.await;
		if attempt == 3 {
			expect(&mut client, "* BYE too many failures\r\n").await;
		}
		expect(&mut client, &format!("A{attempt} NO LOGIN failed\r\n")).await;
	}
	closed(&mut client).await;
	let mut control = server.authenticated().await;
	logout(&mut control).await;
	server.healthy().await;
}

#[tokio::test]
async fn starttls_does_not_execute_pipelined_plaintext_commands() {
	let server = Harness::start(|s| s).await;
	// A control handshake rules out broken certificates as an attack result.
	let mut control = server.authenticated().await;
	logout(&mut control).await;
	let mut client = server.connect().await;
	send(
		&mut client,
		format!("T STARTTLS\r\nE LOGIN tester {PASSWORD}\r\nF CREATE forged\r\nX LOGOUT\r\n")
			.as_bytes(),
	)
	.await;
	expect(&mut client, "T OK begin TLS now\r\n").await;
	// Any plaintext IMAP response after the boundary proves execution.
	let mut byte = [0];
	if let Ok(result) = tokio::time::timeout(
		std::time::Duration::from_millis(100),
		client.peek(&mut byte),
	)
	.await
	{
		match result {
			Ok(0) => {}
			// A TLS alert is valid if unread plaintext reached the acceptor.
			Ok(_) if byte[0] == 0x15 => {}
			Err(e) if is_close(&e) => {}
			other => panic!("plaintext response after STARTTLS: {other:?}"),
		}
	}
	match server.try_upgrade(client).await {
		Ok(mut client) => {
			send(&mut client, b"V SELECT INBOX\r\n").await;
			expect(&mut client, "V NO not authenticated\r\n").await;
			send(
				&mut client,
				format!("L LOGIN tester {PASSWORD}\r\n").as_bytes(),
			)
			.await;
			expect(&mut client, "L OK LOGIN completed\r\n").await;
			noop(&mut client).await;
			logout(&mut client).await;
		}
		Err(e) => assert!(
			is_close(&e)
				|| matches!(
					e.kind(),
					std::io::ErrorKind::InvalidData | std::io::ErrorKind::BrokenPipe
				),
			"unexpected TLS failure: {e:?}"
		),
	}
	assert!(!epistle::imap::mailbox::exists(
		server.data.path(),
		"tester",
		"forged"
	));
	let mut control = server.authenticated().await;
	logout(&mut control).await;
	server.healthy().await;
}
