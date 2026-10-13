//! The server sends the DSN for a recipient whose mailbox a message would
//! overfill, once the message is delivered to the others.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::smtp::sink::MemorySink;

#[tokio::test]
async fn the_mailbox_full_dsn_follows_the_delivered_message() {
	let sink = Arc::new(MemorySink::new());
	let directory = Directory::new(
		["example.org".to_string()],
		[
			("bob@example.org".to_string(), "bob".to_string()),
			("carol@example.org".to_string(), "carol".to_string()),
		],
	)
	.with_account_quotas([("bob".to_string(), 100)]);
	let quota = crate::smtp::quota::MailboxQuota::new(
		|account| if account == "bob" { 95 } else { 0 },
		1 << 30,
	);
	let server = Server::new("mx.example.org", sink.clone() as Arc<dyn MessageSink>)
		.with_directory(DirectoryHandle::new(directory))
		.with_quota(Arc::new(quota));
	let (client, server_stream) = tokio::io::duplex(64 * 1024);
	let task = tokio::spawn(async move { server.handle(server_stream, None).await });
	let (mut read, mut write) = tokio::io::split(client);
	write
		.write_all(
			b"EHLO client.example.net\r\nMAIL FROM:<alice@sender.example>\r\n\
RCPT TO:<bob@example.org>\r\nRCPT TO:<carol@example.org>\r\nDATA\r\n\
Subject: hi\r\n\r\nthis body is longer than five bytes\r\n.\r\nQUIT\r\n",
		)
		.await
		.expect("write");
	write.shutdown().await.expect("shutdown");
	let mut output = Vec::new();
	read.read_to_end(&mut output).await.expect("read");
	task.await.expect("task").expect("server");

	let output = String::from_utf8(output).expect("ascii");
	assert!(output.contains("250 2.0.0 ok\r\n221"), "{output}");
	let messages = sink.messages();
	assert_eq!(messages.len(), 2, "the message, then the DSN");
	assert_eq!(
		messages[0].recipients,
		vec!["carol@example.org".to_string()]
	);
	assert_eq!(messages[1].reverse_path, "");
	assert_eq!(
		messages[1].recipients,
		vec!["alice@sender.example".to_string()]
	);
	let dsn = String::from_utf8_lossy(&messages[1].data);
	assert!(
		dsn.contains("Final-Recipient: rfc822; bob@example.org"),
		"{dsn}"
	);
	assert!(dsn.contains("Status: 5.2.2"), "{dsn}");
}
