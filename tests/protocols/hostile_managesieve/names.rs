//! Script-name validation and account-scoped activation.

use super::harness::*;

const INVALID_NAME: &str = "NO \"Invalid script name: use 1 to 128 characters and at most 512 bytes, in Unicode normal form C, with no slash, backslash, control or bidirectional character, no space at either end, and not . or .., for example keep-spam.\"\r\n";

async fn invalid_name(name: &str) {
	let server = Harness::start(|s| s).await;
	let mut client = server.login("tester").await;
	let sentinel = server.data.path().join("accounts/victim/filter.sieve");
	std::fs::write(&sentinel, b"discard;").expect("victim sentinel");
	put(&mut client, name, "keep;").await;
	expect(&mut client, INVALID_NAME).await;
	send(&mut client, b"LISTSCRIPTS\r\n").await;
	expect(&mut client, "OK \"Listed.\"\r\n").await;
	assert_eq!(
		std::fs::read(sentinel).expect("victim sentinel"),
		b"discard;"
	);
	logout(&mut client).await;
	server.healthy().await;
}

#[tokio::test]
async fn traversal_script_name_cannot_escape_the_account() {
	invalid_name("../victim/filter").await;
}

#[tokio::test]
async fn name_over_128_characters_is_rejected_by_the_store() {
	invalid_name(&"x".repeat(129)).await;
}

#[tokio::test]
async fn nul_in_script_name_closes_before_writing_a_script() {
	let server = Harness::start(|s| s).await;
	let mut client = server.login("tester").await;
	send(&mut client, b"PUTSCRIPT \"bad\0name\" {5+}\r\nkeep;\r\n").await;
	expect(&mut client, "BYE \"Pre-authentication timeout.\"\r\n").await;
	closed(&mut client).await;
	assert!(
		!server
			.data
			.path()
			.join("accounts/tester/sieve/bad.sieve")
			.exists()
	);
	server.healthy().await;
}

#[tokio::test]
async fn thousand_octet_name_closes_at_the_line_decoder() {
	let server = Harness::start(|s| s).await;
	let mut client = server.login("tester").await;
	send(
		&mut client,
		format!("PUTSCRIPT \"{}\" {{5+}}\r\nkeep;\r\n", "x".repeat(1000)).as_bytes(),
	)
	.await;
	expect(&mut client, "BYE \"Pre-authentication timeout.\"\r\n").await;
	closed(&mut client).await;
	server.healthy().await;
}

#[tokio::test]
async fn setactive_cannot_select_or_modify_another_accounts_script() {
	let server = Harness::start(|s| s).await;
	let mut victim = server.login("victim").await;
	put(&mut victim, "private", "discard;").await;
	expect(&mut victim, "OK\r\n").await;
	send(&mut victim, b"SETACTIVE \"private\"\r\n").await;
	expect(&mut victim, "OK\r\n").await;
	logout(&mut victim).await;
	let root = server.data.path().join("accounts/victim");
	let original_live = std::fs::read(root.join("filter.sieve")).expect("victim active script");
	let original_marker = std::fs::read(root.join("sieve/.active")).expect("victim marker");
	let mut client = server.login("tester").await;
	for command in ["SETACTIVE \"private\"\r\n", "GETSCRIPT \"private\"\r\n"] {
		send(&mut client, command.as_bytes()).await;
		expect(&mut client, "NO (NONEXISTENT) \"No such script.\"\r\n").await;
	}
	send(&mut client, b"SETACTIVE \"../victim/sieve/private\"\r\n").await;
	expect(&mut client, INVALID_NAME).await;
	assert!(
		!server
			.data
			.path()
			.join("accounts/tester/filter.sieve")
			.exists()
	);
	// Identical names must resolve to each authenticated account's own store.
	put(&mut client, "private", "keep;").await;
	expect(&mut client, "OK\r\n").await;
	send(&mut client, b"SETACTIVE \"private\"\r\n").await;
	expect(&mut client, "OK\r\n").await;
	assert_eq!(
		std::fs::read(server.data.path().join("accounts/tester/filter.sieve")).expect("own filter"),
		b"keep;"
	);
	assert_eq!(
		std::fs::read(root.join("filter.sieve")).expect("victim filter"),
		original_live
	);
	assert_eq!(
		std::fs::read(root.join("sieve/.active")).expect("victim marker"),
		original_marker
	);
	assert_eq!(
		std::fs::read(root.join("sieve/private.sieve")).expect("victim source"),
		b"discard;"
	);
	logout(&mut client).await;
	server.healthy().await;
}
