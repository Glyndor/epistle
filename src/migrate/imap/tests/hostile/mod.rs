//! A real migration client talking to a byte-scripted loopback peer.

mod framing;

use crate::migrate::imap::client::Client;
use crate::migrate::imap::transport::{Endpoint, Security, Verify};
use crate::migrate::imap::wire::Limits;
use crate::migrate::tests::{DEADLINE, Peer};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

const LIMIT: usize = 4096;

async fn client(reply: Vec<u8>) -> (Client, Peer) {
	let listener = TcpListener::bind("127.0.0.1:0")
		.await
		.expect("bind IMAP peer");
	let address = listener.local_addr().expect("address");
	let peer = Peer(tokio::spawn(async move {
		let serve = async move {
			let (tcp, _) = listener.accept().await.expect("accept");
			let mut conn = BufReader::new(tcp);
			conn.get_mut()
				.write_all(b"* OK hostile peer ready\r\n")
				.await
				.expect("greeting");
			let mut line = String::new();
			conn.read_line(&mut line).await.expect("capability");
			assert_eq!(line, "M1 CAPABILITY\r\n");
			conn.get_mut()
				.write_all(b"* CAPABILITY IMAP4rev1\r\nM1 OK caps\r\n")
				.await
				.expect("caps");
			line.clear();
			conn.read_line(&mut line).await.expect("fetch");
			assert!(line.starts_with("M2 UID FETCH 1 "), "{line:?}");
			conn.get_mut().write_all(&reply).await.expect("attack");
			// Keep the socket open: EOF must not be what stops the client.
			std::future::pending::<()>().await;
		};
		let _ = tokio::time::timeout(DEADLINE * 2, serve).await;
	}));
	let endpoint = Endpoint {
		host: "127.0.0.1".into(),
		port: address.port(),
		address: Some(address),
		security: Security::Plaintext,
		verify: Verify::Roots { extra: vec![] },
	};
	let limits = Limits {
		line: 4096,
		literal: LIMIT,
		idle: std::time::Duration::from_millis(400),
		response: std::time::Duration::from_secs(1),
	};
	let client = tokio::time::timeout(DEADLINE, Client::connect(&endpoint, limits))
		.await
		.expect("connect deadline")
		.expect("connect");
	(client, peer)
}

fn body_reply(body: &[u8], tail: &[u8]) -> Vec<u8> {
	let mut out = format!(
		"* 1 FETCH (UID 1 RFC822.SIZE {} BODY[] {{{}}}\r\n",
		body.len(),
		body.len()
	)
	.into_bytes();
	out.extend_from_slice(body);
	out.extend_from_slice(b")\r\n");
	out.extend_from_slice(tail);
	out
}
