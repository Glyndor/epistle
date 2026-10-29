use super::*;
use tokio::io::AsyncWriteExt;

#[test]
fn uid_sets_are_compact() {
	assert_eq!(uid_set(&[1, 2, 3, 5, 7, 8]), "1:3,5,7:8");
	assert_eq!(uid_set(&[4]), "4");
	assert_eq!(uid_set(&[]), "");
}

#[test]
fn quoting_escapes_and_refuses_line_breaks() {
	assert_eq!(quote(br#"a"b\c"#), br#""a\"b\\c""#.to_vec());
	assert!(quote_mailbox(b"a\r\nb").is_err());
	assert!(quote_mailbox(b"a\0b").is_err());
}

#[test]
fn server_text_is_sanitized_and_short() {
	assert_eq!(sanitize(b"bad\x1b[31m\xff"), "bad?[31m?");
	assert_eq!(sanitize(&[b'a'; 500]).len(), 200);
}

#[test]
fn a_body_may_exceed_its_declared_size_only_slightly() {
	assert!(size_fits(1000, 1000));
	assert!(size_fits(1000, 1000 + 100 + 4096));
	assert!(!size_fits(1000, 1000 + 100 + 4097));
	assert!(!size_fits(1024, 300 * 1024));
	assert!(size_fits(0, 4096));
}

pub(in super::super) fn memory_client(stream: tokio::io::DuplexStream) -> Client {
	Client {
		conn: BufReader::new(Box::new(stream)),
		limits: Limits {
			line: 64 * 1024,
			literal: 2 * 1024 * 1024,
			idle: std::time::Duration::from_secs(10),
			response: std::time::Duration::from_secs(2),
		},
		tag: 0,
		capabilities: Vec::new(),
		deadline: None,
		read_literal: MAX_NAME_BYTES,
		metadata: Budget::default(),
		response_budget: 128 * 1024 * 1024,
	}
}

#[tokio::test(start_paused = true)]
async fn complete_keepalives_cannot_extend_a_command() {
	use std::time::Duration;
	use tokio::io::AsyncBufReadExt;
	let (stream, peer) = tokio::io::duplex(128);
	let mut client = memory_client(stream);
	let server = tokio::spawn(async move {
		let mut peer = BufReader::new(peer);
		let mut command = String::new();
		peer.read_line(&mut command).await.expect("command");
		loop {
			peer.get_mut()
				.write_all(b"* OK keepalive\r\n")
				.await
				.expect("keepalive");
			tokio::time::sleep(Duration::from_millis(500)).await;
		}
	});
	let result = tokio::time::timeout(Duration::from_secs(5), client.list()).await;
	server.abort();
	assert!(
		matches!(
			result,
			Ok(Err(ClientError::CommandTimeout { command: "LIST" }))
		),
		"the command must stop before the external guard"
	);
}

#[tokio::test(start_paused = true)]
async fn the_command_deadline_also_bounds_writes() {
	let (stream, _peer) = tokio::io::duplex(1);
	let mut client = memory_client(stream);
	let result = tokio::time::timeout(std::time::Duration::from_secs(5), client.list()).await;
	assert!(
		matches!(
			result,
			Ok(Err(ClientError::CommandTimeout { command: "LIST" }))
		),
		"a blocked command write must stop"
	);
}

#[tokio::test]
async fn mailbox_literals_have_a_separate_small_limit() {
	use tokio::io::AsyncBufReadExt;
	let (stream, peer) = tokio::io::duplex(4096);
	let mut client = memory_client(stream);
	let server = tokio::spawn(async move {
		let mut peer = BufReader::new(peer);
		let mut command = String::new();
		peer.read_line(&mut command).await.expect("command");
		peer.get_mut()
			.write_all(b"* LIST () \"/\" {2048}\r\n")
			.await
			.expect("marker");
		peer.get_mut()
			.write_all(&vec![b'x'; 2048])
			.await
			.expect("literal");
		peer.get_mut()
			.write_all(b"\r\nM1 OK done\r\n")
			.await
			.expect("done");
	});
	assert!(
		client.list().await.is_err(),
		"a mailbox name is not a message body"
	);
	server.await.expect("server");
}

pub(in super::super) async fn scripted_client(
	replies: Vec<Vec<u8>>,
) -> (Client, tokio::task::JoinHandle<()>) {
	use tokio::io::AsyncBufReadExt;
	let (stream, peer) = tokio::io::duplex(64 * 1024);
	let server = tokio::spawn(async move {
		let mut peer = BufReader::new(peer);
		for reply in replies {
			let mut command = String::new();
			if peer.read_line(&mut command).await.expect("command") == 0 {
				return;
			}
			if peer.get_mut().write_all(&reply).await.is_err() {
				return;
			}
		}
	});
	(memory_client(stream), server)
}

#[tokio::test]
async fn list_and_uid_metadata_have_independent_byte_budgets() {
	for total in [false, true] {
		let mut reply = Vec::new();
		for uid in 1..=8 {
			reply.extend_from_slice(
				format!("* {uid} FETCH (UID {uid} RFC822.SIZE 1)\r\n").as_bytes(),
			);
		}
		reply.extend_from_slice(b"M1 OK done\r\n");
		let (mut client, server) = scripted_client(vec![reply]).await;
		if total {
			client.metadata.total_limit = 64;
		} else {
			client.metadata.mailbox_limit = 64;
		}
		let result = client.list_uids(1, None, u32::MAX as usize).await;
		assert!(
			matches!(result, Err(ClientError::Metadata { scope, limit: 64 }) if scope == if total { "total" } else { "mailbox" })
		);
		server.await.expect("server");
	}
	let reply =
		b"* LIST () \"/\" \"INBOX\"\r\n* LIST () \"/\" \"Other\"\r\nM1 OK done\r\n".to_vec();
	let (mut client, server) = scripted_client(vec![reply]).await;
	client.metadata.total_limit = 400;
	assert!(matches!(
		client.list().await,
		Err(ClientError::Metadata { scope: "total", .. })
	));
	server.await.expect("server");
}

#[tokio::test]
async fn flags_are_charged_even_when_message_bodies_are_small() {
	let reply = format!(
		"* 1 FETCH (UID 1 FLAGS ({}) RFC822.SIZE 1 BODY[] {{1}}\r\na)\r\nM1 OK done\r\n",
		"keyword ".repeat(100)
	)
	.into_bytes();
	let (mut client, server) = scripted_client(vec![reply]).await;
	client.metadata.mailbox_limit = 512;
	assert!(matches!(
		client.fetch(&[Listed { uid: 1, size: 1 }], 10).await,
		Err(ClientError::Metadata {
			scope: "mailbox",
			..
		})
	));
	server.await.expect("server");
}

#[tokio::test]
async fn command_response_bytes_are_bounded() {
	let (mut client, server) =
		scripted_client(vec![b"* OK one\r\n* OK two\r\nM1 OK done\r\n".to_vec()]).await;
	client.response_budget = 10;
	assert!(
		matches!(client.list().await, Err(ClientError::Protocol(text)) if text.contains("response budget"))
	);
	server.await.expect("server");
}

#[tokio::test]
async fn quoted_names_and_namespace_literals_are_bounded() {
	let reply = format!("* LIST () \"/\" \"{}\"\r\nM1 OK done\r\n", "a".repeat(1025)).into_bytes();
	let (mut client, server) = scripted_client(vec![reply]).await;
	assert!(matches!(
		client.list().await,
		Err(ClientError::Metadata {
			scope: "mailbox name",
			..
		})
	));
	server.await.expect("server");
	let (mut client, server) = scripted_client(vec![b"* NAMESPACE (({2048}\r\n".to_vec()]).await;
	client.capabilities.push("NAMESPACE".into());
	assert!(matches!(
		client.namespace().await,
		Err(ClientError::Wire(WireError::LiteralTooLarge {
			limit: 1024,
			..
		}))
	));
	server.await.expect("server");
}

#[tokio::test]
async fn the_total_budget_survives_successful_commands_and_mailbox_changes() {
	let replies = vec![
		b"* 1 FETCH (UID 1 RFC822.SIZE 1)\r\n* 2 FETCH (UID 2 RFC822.SIZE 1)\r\nM1 OK done\r\n"
			.to_vec(),
		b"M2 OK examined\r\n".to_vec(),
		b"* 3 FETCH (UID 3 RFC822.SIZE 1)\r\nM3 OK done\r\n".to_vec(),
	];
	let (mut client, server) = scripted_client(replies).await;
	client.metadata.total_limit = 64;
	assert_eq!(
		client
			.list_uids(1, None, 2)
			.await
			.expect("first page")
			.len(),
		2
	);
	client.examine(b"Other").await.expect("next mailbox");
	assert!(matches!(
		client.list_uids(3, None, 1).await,
		Err(ClientError::Metadata {
			scope: "total",
			limit: 64
		})
	));
	server.await.expect("server");
}

#[tokio::test(start_paused = true)]
async fn authentication_continuations_share_the_original_deadline() {
	use std::time::Duration;
	use tokio::io::AsyncBufReadExt;
	let (stream, peer) = tokio::io::duplex(32);
	let mut client = memory_client(stream);
	let server = tokio::spawn(async move {
		let mut peer = BufReader::new(peer);
		let mut command = String::new();
		peer.read_line(&mut command).await.expect("command");
		tokio::time::sleep(Duration::from_millis(1500)).await;
		peer.get_mut()
			.write_all(b"+ go\r\n")
			.await
			.expect("continuation");
		std::future::pending::<()>().await;
	});
	let started = tokio::time::Instant::now();
	let result = tokio::time::timeout(
		Duration::from_secs(5),
		client.authenticate_plain("alice", &crate::test_fixtures::password().repeat(20)),
	)
	.await;
	server.abort();
	assert!(matches!(
		result,
		Ok(Err(ClientError::CommandTimeout {
			command: "AUTHENTICATE"
		}))
	));
	assert!(
		started.elapsed() < Duration::from_millis(2500),
		"the continuation must not restart the command clock"
	);
}

#[tokio::test]
async fn uids_outside_a_requested_window_are_refused() {
	let (mut client, server) = scripted_client(vec![
		b"* 1 FETCH (UID 3 RFC822.SIZE 1)\r\nM1 OK done\r\n".to_vec(),
	])
	.await;
	assert!(
		matches!(client.list_uids(1, Some(2), 10).await, Err(ClientError::Protocol(text)) if text.contains("outside the requested window"))
	);
	server.await.expect("server");
}

#[tokio::test]
async fn empty_responses_consume_the_command_byte_budget() {
	let (mut client, server) = scripted_client(vec![b"\r\n\r\n\r\n".to_vec()]).await;
	client.response_budget = 4;
	assert!(
		matches!(client.list().await, Err(ClientError::Protocol(text)) if text.contains("response budget"))
	);
	server.await.expect("server");
}
