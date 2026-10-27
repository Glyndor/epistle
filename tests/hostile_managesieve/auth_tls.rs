//! STARTTLS and authentication state guards on the real listener.

use super::harness::*;

#[tokio::test]
async fn valid_plain_credentials_are_refused_without_tls() {
	let server = Harness::start(|s| s).await;
	let mut client = server.connect().await;
	send(&mut client, authentication("tester", PASSWORD).as_bytes()).await;
	expect(
		&mut client,
		"NO (ENCRYPT-NEEDED) \"TLS is required first.\"\r\n",
	)
	.await;
	send(&mut client, b"LISTSCRIPTS\r\n").await;
	expect(&mut client, "NO \"Authenticate first.\"\r\n").await;
	logout(&mut client).await;
	let mut control = server.login("tester").await;
	logout(&mut control).await;
	server.healthy().await;
}

async fn denied<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(client: &mut S) {
	for command in [
		"LISTSCRIPTS\r\n",
		"GETSCRIPT \"private\"\r\n",
		"SETACTIVE \"private\"\r\n",
		"DELETESCRIPT \"private\"\r\n",
		"RENAMESCRIPT \"private\" \"stolen\"\r\n",
		"PUTSCRIPT \"forged\" {5+}\r\nkeep;\r\n",
	] {
		send(client, command.as_bytes()).await;
		expect(client, "NO \"Authenticate first.\"\r\n").await;
	}
	// A rejected synchronizing literal must not wait for its body.
	send(client, b"PUTSCRIPT \"forged\" {5}\r\nNOOP \"probe\"\r\n").await;
	expect(client, "NO \"Authenticate first.\"\r\n").await;
	expect(client, "OK \"probe\"\r\n").await;
}

#[tokio::test]
async fn script_commands_before_login_never_read_write_or_activate() {
	let server = Harness::start(|s| s).await;
	let mut owner = server.login("tester").await;
	put(&mut owner, "private", "discard;").await;
	expect(&mut owner, "OK\r\n").await;
	logout(&mut owner).await;
	let mut plain = server.connect().await;
	denied(&mut plain).await;
	logout(&mut plain).await;
	let mut encrypted = server.encrypted().await;
	denied(&mut encrypted).await;
	logout(&mut encrypted).await;
	let root = server.data.path().join("accounts/tester");
	assert_eq!(
		std::fs::read(root.join("sieve/private.sieve")).expect("private script"),
		b"discard;"
	);
	assert!(!root.join("sieve/forged.sieve").exists());
	assert!(!root.join("sieve/stolen.sieve").exists());
	assert!(!root.join("filter.sieve").exists());
	server.healthy().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn third_failed_authentication_closes_despite_interleaved_noops() {
	let server = Harness::start(|s| s).await;
	let mut client = server.encrypted().await;
	for attempt in 1..=3 {
		send(
			&mut client,
			authentication("tester", "WrongFixture37!").as_bytes(),
		)
		.await;
		if attempt == 3 {
			expect(&mut client, "BYE \"Too many authentication failures.\"\r\n").await;
		} else {
			expect(&mut client, "NO \"Authentication failed.\"\r\n").await;
			send(&mut client, b"NOOP\r\n").await;
			expect(&mut client, "OK\r\n").await;
		}
	}
	closed(&mut client).await;
	let mut control = server.login("tester").await;
	logout(&mut control).await;
	server.healthy().await;
}

#[tokio::test]
async fn starttls_discards_pipelined_plaintext_authentication() {
	let server = Harness::start(|s| s).await;
	let mut control = server.login("tester").await;
	logout(&mut control).await;
	let mut client = server.connect().await;
	let injected = format!(
		"STARTTLS\r\n{}SETACTIVE \"private\"\r\n",
		authentication("tester", PASSWORD)
	);
	send(&mut client, injected.as_bytes()).await;
	expect(&mut client, "OK \"Begin TLS negotiation now.\"\r\n").await;
	match server.upgrade(client).await {
		Ok(mut client) => {
			greeting(&mut client, true).await;
			send(&mut client, b"LISTSCRIPTS\r\n").await;
			expect(&mut client, "NO \"Authenticate first.\"\r\n").await;
			logout(&mut client).await;
		}
		Err(e) => assert!(
			is_close(&e)
				|| matches!(
					e.kind(),
					std::io::ErrorKind::InvalidData | std::io::ErrorKind::BrokenPipe
				),
			"{e:?}"
		),
	}
	assert!(
		!server
			.data
			.path()
			.join("accounts/tester/filter.sieve")
			.exists()
	);
	server.healthy().await;
}
