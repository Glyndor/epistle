use super::super::{DEADLINE, Peer};
use crate::storage::S3Backend;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

pub(super) async fn start(body: &'static [u8]) -> (S3Backend, Peer) {
	let listener = TcpListener::bind("127.0.0.1:0")
		.await
		.expect("bind S3 peer");
	let address = listener.local_addr().expect("address");
	let peer = Peer(tokio::spawn(async move {
		tokio::time::timeout(DEADLINE * 2, async move {
			let (tcp, _) = listener.accept().await.expect("accept");
			let mut tcp = BufReader::new(tcp);
			let mut line = String::new();
			tcp.read_line(&mut line).await.expect("request");
			assert_eq!(line, "GET /mail/?list-type=2 HTTP/1.1\r\n");
			let mut signed = false;
			for _ in 0..64 {
				line.clear();
				assert!(tcp.read_line(&mut line).await.expect("header") <= 8192);
				signed |= line
					.to_ascii_lowercase()
					.starts_with("authorization: aws4-hmac-sha256");
				if line == "\r\n" {
					break;
				}
			}
			assert!(signed, "production request must be signed");
			let content_type = if body.starts_with(b"{") {
				"application/json"
			} else {
				"application/xml"
			};
			let header = format!(
				"HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\r\n",
				body.len()
			);
			tcp.get_mut()
				.write_all(header.as_bytes())
				.await
				.expect("headers");
			tcp.get_mut().write_all(body).await.expect("body");
			// Keep TCP open after the declared body: a transport EOF must
			// not masquerade as parser rejection.
			std::future::pending::<()>().await;
		})
		.await
		.ok();
	}));
	let backend = S3Backend::new(
		format!("http://{address}"),
		"mail".into(),
		"us-east-1".into(),
		"AKID".into(),
		uuid::Uuid::now_v7().to_string(),
	);
	(backend, peer)
}
