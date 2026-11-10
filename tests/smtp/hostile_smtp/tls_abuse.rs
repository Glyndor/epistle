//! Handshake abuse after `STARTTLS`: hello messages an attacker builds by
//! hand, with a hostile SNI, thousands of extensions, an unknown ALPN or a
//! record longer than TLS allows, while the certificate is reloaded.
//!
//! The listener must answer with an alert or close, never hand out a
//! session, never deliver mail, and keep serving a real handshake afterwards.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::harness::*;
use super::tls::Tls;
use crate::common::TLS_PROBE_IO_TIMEOUT;

fn u16_be(n: usize) -> [u8; 2] {
	u16::try_from(n).expect("fits u16").to_be_bytes()
}

fn extension(kind: u16, body: &[u8]) -> Vec<u8> {
	let mut out = kind.to_be_bytes().to_vec();
	out.extend(u16_be(body.len()));
	out.extend(body);
	out
}

/// SNI extension naming `host`, with no check on what the bytes are.
fn sni(host: &[u8]) -> Vec<u8> {
	let mut entry = vec![0];
	entry.extend(u16_be(host.len()));
	entry.extend(host);
	let mut list = u16_be(entry.len()).to_vec();
	list.extend(entry);
	extension(0, &list)
}

fn alpn(protocols: &[&[u8]]) -> Vec<u8> {
	let mut list = Vec::new();
	for protocol in protocols {
		list.push(u8::try_from(protocol.len()).expect("short protocol"));
		list.extend(*protocol);
	}
	let mut body = u16_be(list.len()).to_vec();
	body.extend(list);
	extension(16, &body)
}

/// A TLS 1.3 ClientHello inside one record, carrying `extensions` as given.
fn client_hello(extensions: &[Vec<u8>]) -> Vec<u8> {
	let mut body = vec![3, 3];
	body.extend([7u8; 32]);
	body.push(0);
	body.extend([0, 2, 0x13, 0x01]);
	body.extend([1, 0]);
	let all: Vec<u8> = extensions.concat();
	body.extend(u16_be(all.len()));
	body.extend(all);
	let mut handshake = vec![1, 0];
	handshake.extend(u16_be(body.len()));
	handshake.extend(body);
	let mut record = vec![22, 3, 1];
	record.extend(u16_be(handshake.len()));
	record.extend(handshake);
	record
}

/// Open a connection that has just agreed to STARTTLS.
async fn upgraded(server: &Harness) -> TcpStream {
	let mut tcp = server.connect().await;
	ehlo(&mut tcp).await;
	send(&mut tcp, b"STARTTLS\r\n").await;
	expect(&mut tcp, "220 ready to start TLS\r\n").await;
	tcp
}

/// Whatever the listener answers to `bytes` must be an alert record or
/// nothing, and the connection must end rather than carry on.
async fn refused(server: &Harness, bytes: &[u8]) {
	let mut tcp = upgraded(server).await;
	// The server may close before reading all of a large hello.
	let _ = timeout(TLS_PROBE_IO_TIMEOUT, tcp.write_all(bytes)).await;
	let mut seen: Vec<u8> = Vec::new();
	let outcome = timeout(TLS_PROBE_IO_TIMEOUT, async {
		let mut chunk = [0u8; 512];
		loop {
			match tcp.read(&mut chunk).await {
				Ok(0) => return,
				Ok(n) => {
					seen.extend(&chunk[..n]);
					assert!(seen.len() <= 4096, "unbounded answer to a hostile hello");
				}
				Err(_) => return,
			}
		}
	})
	.await;
	assert!(
		outcome.is_ok(),
		"the connection stayed open after a hostile hello"
	);
	if let Some(first) = seen.first() {
		assert_eq!(
			*first, 21,
			"answered with a record that is not an alert: {seen:?}"
		);
	}
	assert!(server.sink.messages().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hostile_hellos_end_in_an_alert_or_a_close() {
	if !super::enabled() {
		return;
	}
	let tls = Tls::new();
	let server = Harness::start(|s| tls.server(s)).await;
	// The handshake the attacks target works before and after them.
	let mut control = tls.connect(&server).await;
	quit(&mut control).await;

	let sixty_four_kib = vec![b'a'; 64 * 1024 - 64];
	let many: Vec<Vec<u8>> = (0..10_000u16)
		.map(|n| extension(0xff00 + n % 200, &[]))
		.collect();
	let cases: Vec<(&str, Vec<u8>)> = vec![
		("SNI of 64 KiB", client_hello(&[sni(&sixty_four_kib)])),
		(
			"SNI with NUL",
			client_hello(&[sni(b"mx.epistle.test\0.evil.test")]),
		),
		(
			"SNI with CRLF",
			client_hello(&[sni(b"mx.epistle.test\r\nQUIT\r\n")]),
		),
		("empty SNI", client_hello(&[sni(b"")])),
		("SNI as an IP literal", client_hello(&[sni(b"127.0.0.1")])),
		(
			"SNI with high bytes",
			client_hello(&[sni(&[0xff, 0xfe, 0x80, 0x00])]),
		),
		("10k extensions", client_hello(&many)),
		(
			"unknown ALPN",
			client_hello(&[alpn(&[b"smtp-evil", b"h9"])]),
		),
		("empty ALPN entry", client_hello(&[alpn(&[b""])])),
		(
			"same extension twice",
			client_hello(&[sni(b"a.test"), sni(b"b.test")]),
		),
		("hello without extensions", client_hello(&[])),
		("record longer than TLS allows", {
			let mut record = vec![22, 3, 1, 0xff, 0xff];
			record.extend(vec![1u8; 0xffff]);
			record
		}),
		("fatal alert before the hello", vec![21, 3, 3, 0, 2, 2, 40]),
		(
			"application data before the hello",
			vec![23, 3, 3, 0, 4, 1, 2, 3, 4],
		),
		(
			"SSLv2 hello",
			vec![0x80, 0x2e, 1, 0, 2, 0, 0x15, 0, 0, 0, 0x10, 0, 0, 0xff],
		),
		(
			"plain SMTP after the 220",
			b"MAIL FROM:<forged@remote.test>\r\nQUIT\r\n".to_vec(),
		),
	];
	for (name, bytes) in &cases {
		eprintln!("hostile hello: {name}");
		refused(&server, bytes).await;
	}

	let mut after = tls.connect(&server).await;
	quit(&mut after).await;
	server.healthy().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_certificate_reload_while_hostile_hellos_arrive_keeps_serving() {
	if !super::enabled() {
		return;
	}
	let tls = Tls::new();
	let server = Harness::start(|s| tls.server(s)).await;
	let hostile = client_hello(&[sni(b"mx.epistle.test\0"), alpn(&[b"nope"])]);
	for round in 0..20 {
		tls.reload();
		refused(&server, &hostile).await;
		if round % 5 == 0 {
			let mut client = tls.connect(&server).await;
			quit(&mut client).await;
		}
	}
	tls.reload();
	let mut client = tls.connect(&server).await;
	quit(&mut client).await;
	server.healthy().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hello_trickled_one_byte_at_a_time_does_not_pin_the_listener() {
	if !super::enabled() {
		return;
	}
	let tls = Tls::new();
	let server = Harness::start(|s| tls.server(s)).await;
	let mut slow = upgraded(&server).await;
	let hello = client_hello(&[sni(b"mx.epistle.test")]);
	for byte in hello.iter().take(8) {
		slow.write_all(&[*byte]).await.expect("write byte");
		tokio::time::sleep(Duration::from_millis(20)).await;
	}
	// Other clients are served while the slow one is mid-handshake.
	let mut other = tls.connect(&server).await;
	quit(&mut other).await;
	drop(slow);
	server.healthy().await;
}
