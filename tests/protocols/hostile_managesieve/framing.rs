//! Oversized literals, script-size limits and literal command isolation.

use super::harness::*;
use epistle::managesieve::store::MAX_SCRIPT_BYTES;

#[tokio::test]
async fn u32_max_literal_before_login_closes_without_waiting_for_body() {
	let server = Harness::start(|s| s).await;
	let mut client = server.connect().await;
	send(&mut client, b"PUTSCRIPT \"bomb\" {4294967295+}\r\n").await;
	expect(&mut client, "BYE \"literal too large\"\r\n").await;
	closed(&mut client).await;
	server.healthy().await;
}

#[tokio::test]
async fn u32_max_literal_after_login_closes_without_allocating_body() {
	let server = Harness::start(|s| s).await;
	let mut client = server.login("tester").await;
	send(&mut client, b"PUTSCRIPT \"bomb\" {4294967295+}\r\n").await;
	expect(&mut client, "BYE \"literal too large\"\r\n").await;
	closed(&mut client).await;
	assert!(
		!server
			.data
			.path()
			.join("accounts/tester/sieve/bomb.sieve")
			.exists()
	);
	server.healthy().await;
}

#[tokio::test]
async fn configured_literal_limit_rejects_one_octet_over() {
	let server = Harness::start(|s| s.with_max_literal(64)).await;
	let mut client = server.login("tester").await;
	put(&mut client, "boundary", &format!("#{}", "x".repeat(63))).await;
	expect(&mut client, "OK\r\n").await;
	send(&mut client, b"PUTSCRIPT \"oversized\" {65+}\r\n").await;
	expect(&mut client, "BYE \"literal too large\"\r\n").await;
	closed(&mut client).await;
	assert!(
		!server
			.data
			.path()
			.join("accounts/tester/sieve/oversized.sieve")
			.exists()
	);
	server.healthy().await;
}

#[tokio::test]
async fn default_one_mib_literal_limit_rejects_before_body() {
	let server = Harness::start(|s| s).await;
	let mut client = server.login("tester").await;
	send(&mut client, b"PUTSCRIPT \"oversized\" {1048577+}\r\n").await;
	expect(&mut client, "BYE \"literal too large\"\r\n").await;
	closed(&mut client).await;
	server.healthy().await;
}

#[tokio::test]
async fn storage_size_limit_survives_a_larger_transport_limit() {
	let server = Harness::start(|s| s.with_max_literal(MAX_SCRIPT_BYTES + 1)).await;
	let mut client = server.login("tester").await;
	// A valid comment isolates the size check from grammar rejection.
	let script = format!("#{}", "x".repeat(1 << 20));
	put(&mut client, "oversized", &script).await;
	expect(
		&mut client,
		"NO (QUOTA/MAXSIZE) \"Script is too large.\"\r\n",
	)
	.await;
	send(&mut client, b"LISTSCRIPTS\r\n").await;
	expect(&mut client, "OK \"Listed.\"\r\n").await;
	logout(&mut client).await;
	server.healthy().await;
}

#[tokio::test]
async fn rejected_literal_bytes_cannot_execute_embedded_commands() {
	let server = Harness::start(|s| s).await;
	let mut client = server.connect().await;
	let body = "NOOP \"injected\"\r\nLOGOUT\r\n";
	send(
		&mut client,
		format!(
			"PUTSCRIPT \"forged\" {{{}+}}\r\n{body}\r\nNOOP \"probe\"\r\n",
			body.len()
		)
		.as_bytes(),
	)
	.await;
	expect(&mut client, "NO \"Authenticate first.\"\r\n").await;
	expect(&mut client, "OK \"probe\"\r\n").await;
	logout(&mut client).await;
	assert!(
		!server
			.data
			.path()
			.join("accounts/tester/sieve/forged.sieve")
			.exists()
	);
	server.healthy().await;
}
