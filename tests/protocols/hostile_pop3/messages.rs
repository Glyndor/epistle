//! Pathological message numbers and account-scoped deletion transactions.

use super::harness::*;

const MESSAGE: &[u8] = b"Subject: canary\r\n\r\nfirst\r\nsecond\r\n";

async fn argument_attack(command: &[u8], reply: &str) {
	let server = Harness::start(|s| s).await;
	let uid = uuid::Uuid::now_v7().to_string();
	let path = server.seed("tester", &uid, MESSAGE);
	let mut client = server.login("tester", 1).await;
	send(&mut client, command).await;
	expect(&mut client, reply).await;
	send(&mut client, b"STAT\r\n").await;
	expect(&mut client, &format!("+OK 1 {}\r\n", MESSAGE.len())).await;
	quit(&mut client).await;
	assert_eq!(std::fs::read(path).expect("unchanged message"), MESSAGE);
	server.healthy().await;
}

#[tokio::test]
async fn retr_u32_max_is_no_such_message() {
	argument_attack(b"RETR 4294967295\r\n", "-ERR no such message\r\n").await;
}

#[tokio::test]
async fn retr_integer_overflow_is_invalid_command() {
	argument_attack(b"RETR 4294967296\r\n", "-ERR invalid command\r\n").await;
}

#[tokio::test]
async fn list_negative_is_invalid_command() {
	argument_attack(b"LIST -1\r\n", "-ERR invalid command\r\n").await;
}

#[tokio::test]
async fn uidl_of_missing_message_is_no_such_message() {
	argument_attack(b"UIDL 2\r\n", "-ERR no such message\r\n").await;
}

#[tokio::test]
async fn retr_zero_does_not_underflow() {
	argument_attack(b"RETR 0\r\n", "-ERR no such message\r\n").await;
}

#[tokio::test]
async fn top_u32_max_returns_only_the_existing_body() {
	let server = Harness::start(|s| s).await;
	server.seed("tester", &uuid::Uuid::now_v7().to_string(), MESSAGE);
	let mut client = server.login("tester", 1).await;
	send(&mut client, b"TOP 1 4294967295\r\n").await;
	for reply in [
		"+OK top\r\n",
		"Subject: canary\r\n",
		"\r\n",
		"first\r\n",
		"second\r\n",
		".\r\n",
	] {
		expect(&mut client, reply).await;
	}
	// The next reply proves there was no padding up to the requested line count.
	send(&mut client, b"NOOP\r\n").await;
	expect(&mut client, "+OK \r\n").await;
	quit(&mut client).await;
	server.healthy().await;
}

#[tokio::test]
async fn dele_quit_removes_only_the_authenticated_accounts_copy_of_a_uid() {
	let server = Harness::start(|s| s).await;
	let uid = uuid::Uuid::now_v7().to_string();
	let own = server.seed("tester", &uid, MESSAGE);
	let victim_body = b"Subject: victim\r\n\r\nvictim secret\r\n";
	let victim = server.seed("victim", &uid, victim_body);
	let mut client = server.login("tester", 1).await;
	send(&mut client, b"DELE 1\r\n").await;
	expect(&mut client, "+OK message 1 deleted\r\n").await;
	assert!(own.exists(), "DELE must defer the physical delete to QUIT");
	send(&mut client, b"USER victim\r\n").await;
	expect(&mut client, "-ERR already authenticated\r\n").await;
	send(&mut client, format!("PASS {PASSWORD}\r\n").as_bytes()).await;
	expect(&mut client, "-ERR already authenticated\r\n").await;
	quit(&mut client).await;
	assert!(!own.exists());
	assert_eq!(std::fs::read(victim).expect("victim message"), victim_body);
	let mut control = server.login("victim", 1).await;
	send(&mut control, b"RETR 1\r\n").await;
	expect(
		&mut control,
		&format!("+OK {} octets\r\n", victim_body.len()),
	)
	.await;
	for reply in ["Subject: victim\r\n", "\r\n", "victim secret\r\n", ".\r\n"] {
		expect(&mut control, reply).await;
	}
	quit(&mut control).await;
	server.healthy().await;
}

#[tokio::test]
async fn disconnected_dele_is_not_committed() {
	let server = Harness::start(|s| s).await;
	let path = server.seed("tester", &uuid::Uuid::now_v7().to_string(), MESSAGE);
	let mut client = server.login("tester", 1).await;
	send(&mut client, b"DELE 1\r\n").await;
	expect(&mut client, "+OK message 1 deleted\r\n").await;
	abandon(&mut client).await;
	let mut control = server.login("tester", 1).await;
	assert_eq!(std::fs::read(path).expect("uncommitted message"), MESSAGE);
	quit(&mut control).await;
	server.healthy().await;
}
