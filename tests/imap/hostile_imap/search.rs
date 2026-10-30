//! Pathological ranges and recursion are bounded by mailbox size and parser caps.

use super::harness::*;

#[tokio::test]
async fn huge_search_and_fetch_ranges_on_empty_inbox_return_no_data() {
	let server = Harness::start(|s| s).await;
	let mut client = server.authenticated().await;
	assert!(select_inbox(&mut client).await.contains("* 0 EXISTS\r\n"));
	for command in [
		"F FETCH 1:* (FLAGS)",
		"F FETCH 4294967295:* (FLAGS)",
		"F UID FETCH 4294967295:* (FLAGS)",
	] {
		send(&mut client, format!("{command}\r\n").as_bytes()).await;
		expect(&mut client, "F OK FETCH completed\r\n").await;
	}
	for command in [
		"F SEARCH 1:*",
		"F SEARCH 4294967295:*",
		"F UID SEARCH UID 4294967295:*",
		"F SEARCH LARGER 4294967295",
		"F SEARCH OR NOT ALL UID 4294967295:*",
	] {
		send(&mut client, format!("{command}\r\n").as_bytes()).await;
		expect(&mut client, "* SEARCH\r\n").await;
		expect(&mut client, "F OK SEARCH completed\r\n").await;
	}
	noop(&mut client).await;
	logout(&mut client).await;
	server.healthy().await;
}

#[tokio::test]
async fn huge_reversed_range_matches_last_existing_message_without_enumerating_it() {
	let server = Harness::start(|s| s).await;
	let mut client = server.authenticated().await;
	let body = b"Subject: range-canary\r\n\r\nbody\r\n";
	send(
		&mut client,
		format!("A APPEND INBOX {{{}}}\r\n", body.len()).as_bytes(),
	)
	.await;
	expect(&mut client, "+ ready for literal data\r\n").await;
	send(&mut client, body).await;
	send(&mut client, b"\r\n").await;
	let appended = line(&mut client)
		.await
		.expect("APPEND reply")
		.expect("open");
	assert!(appended.starts_with("A OK [APPENDUID "), "{appended:?}");
	assert!(select_inbox(&mut client).await.contains("* 1 EXISTS\r\n"));
	send(&mut client, b"F FETCH 4294967295:* (FLAGS)\r\n").await;
	expect(&mut client, "* 1 FETCH (FLAGS ())\r\n").await;
	expect(&mut client, "F OK FETCH completed\r\n").await;
	send(&mut client, b"F SEARCH 4294967295:*\r\n").await;
	expect(&mut client, "* SEARCH 1\r\n").await;
	expect(&mut client, "F OK SEARCH completed\r\n").await;
	logout(&mut client).await;
	server.healthy().await;
}

#[tokio::test]
async fn search_depth_over_64_is_bad_while_shallow_search_still_works() {
	let server = Harness::start(|s| s).await;
	let mut client = server.authenticated().await;
	select_inbox(&mut client).await;
	for key in [
		format!("{}ALL{}", "(".repeat(64), ")".repeat(64)),
		format!("{}ALL", "NOT ".repeat(64)),
		format!("{}ALL", "OR ALL ".repeat(64)),
	] {
		// Under 512 bytes: the 32 KiB line cap cannot mask the depth guard.
		send(&mut client, format!("F SEARCH {key}\r\n").as_bytes()).await;
		expect(&mut client, "F BAD invalid arguments\r\n").await;
		send(&mut client, b"F SEARCH (OR ALL (NOT ALL))\r\n").await;
		expect(&mut client, "* SEARCH\r\n").await;
		expect(&mut client, "F OK SEARCH completed\r\n").await;
		server.healthy().await;
	}
	logout(&mut client).await;
}

#[tokio::test]
async fn search_with_100000_parentheses_closes_at_line_limit() {
	let server = Harness::start(|s| s).await;
	let mut client = server.authenticated().await;
	select_inbox(&mut client).await;
	let command = format!(
		"F SEARCH {}ALL{}\r\n",
		"(".repeat(100_000),
		")".repeat(100_000)
	);
	// The peer may close while the rest of the oversized line is being sent.
	use tokio::io::AsyncWriteExt;
	match tokio::time::timeout(IO_DEADLINE, client.write_all(command.as_bytes())).await {
		Ok(Ok(())) => {}
		Ok(Err(e)) if is_close(&e) || e.kind() == std::io::ErrorKind::BrokenPipe => {}
		other => panic!("oversized SEARCH write failed: {other:?}"),
	}
	match line(&mut client).await {
		Ok(Some(reply)) => {
			assert_eq!(reply, TOO_LONG);
			closed(&mut client).await;
		}
		Ok(None) => {}
		Err(e) if is_close(&e) => {}
		other => panic!("oversized SEARCH did not close: {other:?}"),
	}
	server.healthy().await;
}
