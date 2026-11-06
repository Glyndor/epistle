//! Hostile TLS handshakes after STARTTLS: garbage, a record that promises more than it
//! sends, and a ClientHello whose server name is a NUL or far too long. The listener must
//! close or answer with an alert, never deliver anything, and stay healthy for the next client.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::harness::*;
use super::tls::Tls;

const READ_BOUND: Duration = Duration::from_secs(12);

async fn started(server: &Harness) -> TcpStream {
	let mut tcp = server.connect().await;
	ehlo(&mut tcp).await;
	send(&mut tcp, b"STARTTLS\r\n").await;
	expect(&mut tcp, "220 ready to start TLS\r\n").await;
	tcp
}

/// Everything the server sends until it closes or the bound passes. A connection that
/// stays open past the bound is a handshake with no deadline, which is the failure.
async fn until_closed(tcp: &mut TcpStream) -> Vec<u8> {
	let mut seen = Vec::new();
	let mut buffer = [0u8; 4096];
	let result = timeout(READ_BOUND, async {
		loop {
			match tcp.read(&mut buffer).await {
				Ok(0) | Err(_) => return,
				Ok(n) => {
					seen.extend_from_slice(&buffer[..n]);
					assert!(seen.len() < 1 << 16, "unbounded answer to a bad handshake");
				}
			}
		}
	})
	.await;
	assert!(result.is_ok(), "the listener kept a bad handshake open");
	seen
}

fn record(kind: u8, body: &[u8]) -> Vec<u8> {
	let mut out = vec![kind, 3, 1];
	out.extend_from_slice(&(body.len() as u16).to_be_bytes());
	out.extend_from_slice(body);
	out
}

fn extension(kind: u16, body: &[u8]) -> Vec<u8> {
	let mut out = kind.to_be_bytes().to_vec();
	out.extend_from_slice(&(body.len() as u16).to_be_bytes());
	out.extend_from_slice(body);
	out
}

/// A TLS 1.3 ClientHello whose server_name extension carries `name` as is.
fn client_hello(name: &[u8]) -> Vec<u8> {
	let mut sni = Vec::new();
	sni.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
	sni.push(0);
	sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
	sni.extend_from_slice(name);
	let mut extensions = extension(0, &sni);
	extensions.extend(extension(0x002b, &[2, 3, 4]));
	extensions.extend(extension(0x000a, &[0, 2, 0, 29]));
	extensions.extend(extension(0x000d, &[0, 2, 8, 4]));
	extensions.extend(extension(0x0033, &[0, 0]));
	let mut hello = vec![3, 3];
	hello.extend_from_slice(&[7u8; 32]);
	hello.push(0);
	hello.extend_from_slice(&[0, 2, 0x13, 0x01]);
	hello.extend_from_slice(&[1, 0]);
	hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
	hello.extend(extensions);
	let mut handshake = vec![1];
	handshake.extend_from_slice(&(hello.len() as u32).to_be_bytes()[1..]);
	handshake.extend(hello);
	record(22, &handshake)
}

async fn attack(bytes: &[u8], half_close: bool) {
	if !super::enabled() {
		return;
	}
	let tls = Tls::new();
	let server = Harness::start(|s| tls.server(s)).await;
	let mut control = tls.connect(&server).await;
	quit(&mut control).await;
	let mut tcp = started(&server).await;
	tcp.write_all(bytes).await.expect("write hostile handshake");
	if half_close {
		tcp.shutdown().await.expect("half close");
	}
	until_closed(&mut tcp).await;
	assert!(server.sink.messages().is_empty());
	let mut after = tls.connect(&server).await;
	quit(&mut after).await;
	server.healthy().await;
}

#[tokio::test]
async fn garbage_instead_of_a_client_hello_is_closed_and_the_listener_lives() {
	attack(&[0xA5; 5000], false).await;
}

#[tokio::test]
async fn a_record_that_promises_more_than_it_sends_is_closed_when_the_peer_stops() {
	let mut bytes = vec![22, 3, 1, 0xFF, 0xFF];
	bytes.extend_from_slice(&[1, 0, 0, 0xF0]);
	attack(&bytes, true).await;
}

#[tokio::test]
async fn a_server_name_with_a_nul_is_refused_or_ignored_without_harm() {
	attack(&client_hello(b"mx.epistle.test\0.evil.example"), false).await;
}

#[tokio::test]
async fn a_server_name_of_64_kib_is_refused_or_ignored_without_harm() {
	attack(&client_hello(&vec![b'a'; 60_000]), false).await;
}

#[tokio::test]
async fn an_empty_server_name_and_a_second_hello_in_the_same_flight_are_survived() {
	let mut bytes = client_hello(b"");
	bytes.extend(client_hello(b"mx.epistle.test"));
	attack(&bytes, false).await;
}
