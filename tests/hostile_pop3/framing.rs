//! Parser and transport bounds, with canaries behind malformed input.

use super::harness::*;

#[tokio::test]
async fn command_over_512_octets_is_rejected_without_setting_user() {
	let server = Harness::start(|s| s).await;
	let mut client = server.connect().await;
	let command = format!("USER {}\r\n", "a".repeat(508));
	send(&mut client, command.as_bytes()).await;
	expect(&mut client, "-ERR invalid command\r\n").await;
	send(&mut client, format!("PASS {PASSWORD}\r\n").as_bytes()).await;
	expect(&mut client, "-ERR USER required first\r\n").await;
	quit(&mut client).await;
	server.healthy().await;
}

#[tokio::test]
async fn unterminated_line_over_decoder_limit_closes() {
	let server = Harness::start(|s| s).await;
	let mut client = server.connect().await;
	send(&mut client, &[b'X'; 1000]).await;
	expect(&mut client, "-ERR line too long\r\n").await;
	closed(&mut client).await;
	server.healthy().await;
}

async fn framing_attack(bytes: &[u8]) {
	let server = Harness::start(|s| s).await;
	let mut client = server.connect().await;
	send(&mut client, bytes).await;
	// The production loop maps every decoder error to this same response.
	expect(&mut client, "-ERR line too long\r\n").await;
	closed(&mut client).await;
	server.healthy().await;
}

#[tokio::test]
async fn nul_inside_user_closes_before_pipelined_pass() {
	framing_attack(b"USER test\0er\r\nPASS canary\r\n").await;
}

#[tokio::test]
async fn bare_cr_cannot_smuggle_a_second_command() {
	framing_attack(b"USER tester\rPASS canary\r\n").await;
}

#[tokio::test]
async fn bare_lf_cannot_smuggle_a_second_command() {
	framing_attack(b"USER tester\nPASS canary\r\n").await;
}

#[tokio::test]
async fn invalid_utf8_command_is_an_error_and_does_not_set_user() {
	let server = Harness::start(|s| s).await;
	let mut client = server.connect().await;
	send(&mut client, b"USER test\xffer\r\n").await;
	expect(&mut client, "-ERR non-ASCII command\r\n").await;
	send(&mut client, b"PASS canary\r\n").await;
	expect(&mut client, "-ERR USER required first\r\n").await;
	quit(&mut client).await;
	server.healthy().await;
}

#[tokio::test]
async fn valid_utf8_high_bytes_are_rejected_by_ascii_parser() {
	let server = Harness::start(|s| s).await;
	let mut client = server.connect().await;
	send(&mut client, "USER téster\r\n".as_bytes()).await;
	expect(&mut client, "-ERR invalid command\r\n").await;
	quit(&mut client).await;
	server.healthy().await;
}
