use super::*;
use base64::Engine;
use tokio::io::{AsyncBufReadExt, BufReader, duplex};

async fn expect_line(
	client: &mut BufReader<tokio::io::DuplexStream>,
	expected: &[u8],
	message: &str,
) {
	let mut bytes = Vec::new();
	tokio::time::timeout(Duration::from_secs(5), client.read_until(b'\n', &mut bytes))
		.await
		.expect("response timeout")
		.expect("read response");
	assert!(bytes == expected, "{message}");
}

#[tokio::test]
async fn pop3_plain_login_and_cancel_over_duplex_wire() {
	let dir = tempfile::tempdir().expect("tempdir");
	let password = crate::smtp::auth::tests::fixture_password();
	let directory = crate::smtp::directory::Directory::new(
		["example.org".into()],
		[("alice@example.org".into(), "alice".into())],
	)
	.with_password_hashes(std::collections::HashMap::from([(
		"alice".into(),
		crate::smtp::auth::tests::hash(password),
	)]));
	let backend = MailboxBackend::new(DirectoryHandle::new(directory), dir.path().into());
	let (client, server) = duplex(4096);
	let task = tokio::spawn(run(server, backend, None));
	let mut client = BufReader::new(client);
	expect_line(
		&mut client,
		b"+OK POP3 ready\r\n",
		"POP3 must send its greeting",
	)
	.await;
	client
		.get_mut()
		.write_all(b"AUTH PLAIN\r\n")
		.await
		.expect("write");
	expect_line(
		&mut client,
		b"+ \r\n",
		"POP3 network loop must send the empty challenge",
	)
	.await;
	client
		.get_mut()
		.write_all(b"*\r\nSTAT\r\n")
		.await
		.expect("write");
	expect_line(
		&mut client,
		b"-ERR authentication cancelled\r\n",
		"POP3 network loop must accept cancellation",
	)
	.await;
	expect_line(
		&mut client,
		b"-ERR authenticate first\r\n",
		"cancelled POP3 login must remain unauthenticated",
	)
	.await;
	client
		.get_mut()
		.write_all(b"AUTH PLAIN\r\n")
		.await
		.expect("write");
	expect_line(
		&mut client,
		b"+ \r\n",
		"POP3 network loop must send the empty challenge",
	)
	.await;
	let encoded = base64::engine::general_purpose::STANDARD.encode(format!("\0alice\0{password}"));
	client
		.get_mut()
		.write_all(format!("{encoded}\r\nSTAT\r\nQUIT\r\n").as_bytes())
		.await
		.expect("write");
	expect_line(
		&mut client,
		b"+OK mailbox ready, 0 messages\r\n",
		"POP3 network loop must consume the SASL response",
	)
	.await;
	expect_line(
		&mut client,
		b"+OK 0 0\r\n",
		"POP3 login must expose the mailbox",
	)
	.await;
	expect_line(&mut client, b"+OK bye\r\n", "POP3 must close after QUIT").await;
	task.await.expect("join").expect("server");
}
