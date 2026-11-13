//! GETMETADATA and SETMETADATA (RFC 5464) take a mailbox name and entry names
//! straight from the client and write a sidecar file, so they get the same
//! hostile names as the mailbox commands, plus entry names of their own.

use super::harness::*;
use super::mailboxes::tree;

/// One command, and every reply line up to its tagged answer.
async fn ask(client: &mut Tls, command: &str) -> Vec<String> {
	send(client, format!("{command}\r\n").as_bytes()).await;
	let mut replies = Vec::new();
	for _ in 0..8 {
		let reply = line(client).await.expect("reply").expect("open");
		let done = reply.starts_with("M ");
		replies.push(reply);
		if done {
			return replies;
		}
	}
	panic!("unbounded reply to {command:?}: {replies:?}");
}

#[tokio::test]
async fn a_traversal_in_the_mailbox_name_writes_and_reads_nothing_outside_the_account() {
	let server = Harness::start(|s| s).await;
	let mut client = server.authenticated().await;
	for dir in ["etc", "accounts/victim"] {
		let path = server.data.path().join(dir);
		std::fs::create_dir_all(&path).expect("protected fixture directory");
		std::fs::write(path.join(".metadata"), b"/private/a Zm9v\n").expect("canary");
	}
	let before = tree(server.data.path());
	for name in [
		"../../etc",
		"INBOX/../..",
		"../victim",
		"a//b",
		"../accounts/victim",
	] {
		assert_eq!(
			ask(
				&mut client,
				&format!("M SETMETADATA \"{name}\" (/private/a \"planted\")")
			)
			.await,
			["M NO no such mailbox\r\n"],
			"{name:?}"
		);
		// The canary has an entry of the same name: a read that escaped would return it.
		assert_eq!(
			ask(&mut client, &format!("M GETMETADATA \"{name}\" /private/a")).await,
			["M NO no such mailbox\r\n"],
			"{name:?}"
		);
		assert_eq!(tree(server.data.path()), before, "{name:?}");
	}
	noop(&mut client).await;
	server.healthy().await;
}

#[tokio::test]
async fn an_entry_name_that_is_not_well_formed_stores_nothing() {
	let server = Harness::start(|s| s).await;
	let mut client = server.authenticated().await;
	assert_eq!(
		ask(&mut client, "M SETMETADATA INBOX (/private/keep \"first\")").await,
		["M OK SETMETADATA completed\r\n"]
	);
	let before = tree(server.data.path());
	for bad in ["private/a", "/", "/a//b", "/a/", "/a*", "/a%", "/a/*/b"] {
		assert_eq!(
			ask(&mut client, &format!("M SETMETADATA INBOX ({bad} \"v\")")).await,
			["M BAD invalid entry name\r\n"],
			"{bad:?}"
		);
		// One good entry before the bad one must not be written either.
		assert_eq!(
			ask(
				&mut client,
				&format!("M SETMETADATA INBOX (/private/early \"v\" {bad} \"w\")")
			)
			.await,
			["M BAD invalid entry name\r\n"],
			"{bad:?}"
		);
		assert_eq!(tree(server.data.path()), before, "{bad:?}");
	}
	// The same shape with a good name is stored, so the refusals above are the name check.
	assert_eq!(
		ask(
			&mut client,
			"M SETMETADATA INBOX (/private/early \"v\" /private/late \"w\")"
		)
		.await,
		["M OK SETMETADATA completed\r\n"]
	);
	assert_ne!(tree(server.data.path()), before);
	server.healthy().await;
}

#[tokio::test]
async fn malformed_argument_lists_are_bad_and_leave_the_session_usable() {
	let server = Harness::start(|s| s).await;
	let mut client = server.authenticated().await;
	let before = tree(server.data.path());
	for bad in [
		"M SETMETADATA INBOX ()",
		"M SETMETADATA INBOX (/private/odd)",
		"M SETMETADATA INBOX /private/a \"v\"",
		"M SETMETADATA INBOX (/private/a \"unterminated)",
		"M SETMETADATA INBOX",
		"M GETMETADATA (MAXSIZE 10 INBOX /private/a",
		"M GETMETADATA INBOX ()",
		"M GETMETADATA",
		"M GETMETADATA INBOX (/private/a",
	] {
		assert_eq!(
			ask(&mut client, bad).await,
			["M BAD invalid arguments\r\n"],
			"{bad:?}"
		);
	}
	assert_eq!(tree(server.data.path()), before);
	noop(&mut client).await;
	server.healthy().await;
}

#[tokio::test]
async fn an_entry_with_a_quote_and_a_backslash_comes_back_escaped() {
	let server = Harness::start(|s| s).await;
	let mut client = server.authenticated().await;
	// Sent as an atom, so the stored name is `/private/a\"b`.
	assert_eq!(
		ask(&mut client, "M SETMETADATA INBOX (/private/a\\\"b \"v\")").await,
		["M OK SETMETADATA completed\r\n"]
	);
	// A response that closed the quoted name early would let a client read `b` as
	// another token.
	assert_eq!(
		ask(&mut client, "M GETMETADATA INBOX (/private/a\\\"b)").await,
		[
			"* METADATA \"INBOX\" (\"/private/a\\\\\\\"b\" {1}\r\n",
			"v)\r\n",
			"M OK GETMETADATA completed\r\n",
		]
	);
	noop(&mut client).await;
	server.healthy().await;
}
