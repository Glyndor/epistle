//! A scripted S3 endpoint speaking raw HTTP, so a case can lie about the
//! length, stall, redirect or page forever in ways a real server never would.

use super::super::{DEADLINE, Peer};
use crate::storage::S3Backend;
use crate::storage::blob_backend::S3Limits as Limits;
use std::sync::{
	Arc,
	atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

#[derive(Clone, Copy)]
pub(super) enum Script {
	/// 200 declaring `length` bytes, of which `sent` ones (value 7) follow.
	/// The socket then stays open and silent.
	Declared { length: u64, sent: usize },
	/// 200 with no length: `chunks` chunks of 64 KiB, then silence.
	Chunked { chunks: usize },
	/// Reads the request and never answers.
	Silent,
	/// 200 declaring 4000 bytes, then one byte every 100 ms.
	Trickle,
	/// Every request is redirected to the same URL.
	Redirect,
	/// A listing page per request, each with `keys` keys. The continuation
	/// token is always the same, or changes each page; the last page (no
	/// token) is request `last`, if any.
	Pages {
		keys: usize,
		same_token: bool,
		last: Option<usize>,
	},
}

const UUID: &str = "0198f2c1-9a4b-7000-8000-";

fn page(keys: usize, request: usize, token: Option<String>) -> Vec<u8> {
	let mut xml = String::from("<?xml version=\"1.0\"?><ListBucketResult>");
	for key in 0..keys {
		xml.push_str(&format!(
			"<Contents><Key>{UUID}{:012x}</Key></Contents>",
			request * 1000 + key
		));
	}
	if let Some(token) = token {
		xml.push_str(&format!(
			"<IsTruncated>true</IsTruncated><NextContinuationToken>{token}</NextContinuationToken>"
		));
	}
	xml.push_str("</ListBucketResult>");
	xml.into_bytes()
}

async fn read_request(tcp: &mut BufReader<TcpStream>) -> bool {
	let mut line = String::new();
	let mut first = true;
	loop {
		line.clear();
		match tcp.read_line(&mut line).await {
			Ok(0) | Err(_) => return false,
			Ok(read) => assert!(read <= 8192, "bounded fake request"),
		}
		if line == "\r\n" {
			return !first;
		}
		first = false;
	}
}

async fn serve(
	mut tcp: BufReader<TcpStream>,
	script: Script,
	requests: Arc<AtomicUsize>,
	url: String,
) {
	while read_request(&mut tcp).await {
		let number = requests.fetch_add(1, Ordering::SeqCst) + 1;
		let out = tcp.get_mut();
		match script {
			Script::Declared { length, sent } => {
				let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {length}\r\n\r\n");
				out.write_all(head.as_bytes()).await.expect("head");
				out.write_all(&vec![7; sent]).await.expect("body");
				std::future::pending::<()>().await;
			}
			Script::Chunked { chunks } => {
				out.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
					.await
					.expect("head");
				for _ in 0..chunks {
					let mut chunk = b"10000\r\n".to_vec();
					chunk.extend_from_slice(&vec![7; 65536]);
					chunk.extend_from_slice(b"\r\n");
					if out.write_all(&chunk).await.is_err() {
						return;
					}
				}
				std::future::pending::<()>().await;
			}
			Script::Silent => std::future::pending::<()>().await,
			Script::Trickle => {
				out.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4000\r\n\r\n")
					.await
					.expect("head");
				loop {
					tokio::time::sleep(Duration::from_millis(100)).await;
					if out.write_all(&[7]).await.is_err() {
						return;
					}
				}
			}
			Script::Redirect => {
				let head =
					format!("HTTP/1.1 302 Found\r\nLocation: {url}\r\nContent-Length: 0\r\n\r\n");
				out.write_all(head.as_bytes()).await.expect("redirect");
			}
			Script::Pages {
				keys,
				same_token,
				last,
			} => {
				let token = if last == Some(number) {
					None
				} else if same_token {
					Some("T".to_string())
				} else {
					Some(format!("T{number}"))
				};
				let body = page(keys, number, token);
				let head = format!(
					"HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: {}\r\n\r\n",
					body.len()
				);
				out.write_all(head.as_bytes()).await.expect("head");
				out.write_all(&body).await.expect("page");
			}
		}
	}
}

/// A backend pointed at the scripted endpoint, the number of requests the
/// endpoint has received, and the endpoint's own handle.
pub(super) async fn start(script: Script, limits: Limits) -> (S3Backend, Arc<AtomicUsize>, Peer) {
	let listener = TcpListener::bind("127.0.0.1:0")
		.await
		.expect("bind S3 peer");
	let address = listener.local_addr().expect("address");
	let requests = Arc::new(AtomicUsize::new(0));
	let seen = requests.clone();
	let url = format!("http://{address}/mail/?list-type=2");
	let peer = Peer(tokio::spawn(async move {
		let mut clients = tokio::task::JoinSet::new();
		while let Ok((tcp, _)) = listener.accept().await {
			let (seen, url) = (seen.clone(), url.clone());
			clients.spawn(async move {
				let _ = tokio::time::timeout(
					DEADLINE * 3,
					serve(BufReader::new(tcp), script, seen, url),
				)
				.await;
			});
		}
	}));
	let backend = S3Backend::with_limits(
		format!("http://{address}"),
		"mail".into(),
		"us-east-1".into(),
		"AKID".into(),
		uuid::Uuid::now_v7().to_string(),
		limits,
	);
	(backend, requests, peer)
}
