//! Malicious Sieve source submitted through authenticated PUTSCRIPT.

use super::harness::*;

async fn rejected_script(script: &str, reason: &str) {
	let server = Harness::start(|s| s).await;
	let mut client = server.login("tester").await;
	put(&mut client, "bomb", script).await;
	expect(&mut client, reason).await;
	send(&mut client, b"LISTSCRIPTS\r\n").await;
	expect(&mut client, "OK \"Listed.\"\r\n").await;
	assert!(
		!server
			.data
			.path()
			.join("accounts/tester/sieve/bomb.sieve")
			.exists()
	);
	// A valid upload proves the command loop and store remain usable.
	put(&mut client, "control", "keep;").await;
	expect(&mut client, "OK\r\n").await;
	logout(&mut client).await;
	server.healthy().await;
}

#[tokio::test]
async fn recursive_blocks_over_64_levels_are_rejected() {
	let script = format!("{}keep;{}", "if true {".repeat(70), "}".repeat(70));
	rejected_script(
		&script,
		"NO \"Script does not parse: line 1: nested more than 64 levels deep\"\r\n",
	)
	.await;
}

#[tokio::test]
async fn recursive_not_chain_over_64_levels_is_rejected() {
	let script = format!("if {}true {{ keep; }}", "not ".repeat(70));
	rejected_script(
		&script,
		"NO \"Script does not parse: line 1: nested more than 64 levels deep\"\r\n",
	)
	.await;
}

#[tokio::test]
async fn self_include_requires_an_unsupported_extension_and_is_rejected() {
	rejected_script(
		"require \"include\"; include :personal \"bomb\";",
		"NO \"Script does not parse: extension \\\"include\\\" is not supported\"\r\n",
	)
	.await;
}

#[tokio::test]
async fn loop_extension_is_rejected_at_upload() {
	rejected_script(
		"require \"foreverypart\";",
		"NO \"Script does not parse: extension \\\"foreverypart\\\" is not supported\"\r\n",
	)
	.await;
}

#[tokio::test]
async fn foreverypart_loop_body_is_rejected_by_the_grammar() {
	rejected_script(
		"require \"foreverypart\"; foreverypart { keep; }",
		"NO \"Script does not parse: line 1: expected ';' after action\"\r\n",
	)
	.await;
}
