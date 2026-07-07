//! Tests for SOCKS5 relay connection (mock proxy on the loopback).

use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A mock SOCKS5 proxy that accepts no-auth CONNECT and then echoes payload.
async fn mock_socks_proxy(reply_code: u8) -> String {
	let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
	let addr = listener.local_addr().expect("addr").to_string();
	tokio::spawn(async move {
		let (mut sock, _) = listener.accept().await.expect("accept");
		// Greeting.
		let mut greet = [0u8; 3];
		sock.read_exact(&mut greet).await.expect("greet");
		sock.write_all(&[0x05, 0x00]).await.expect("method");
		// CONNECT request: ver,cmd,rsv,atyp,len,host...,port(2).
		let mut head = [0u8; 5];
		sock.read_exact(&mut head).await.expect("req head");
		let mut rest = vec![0u8; head[4] as usize + 2];
		sock.read_exact(&mut rest).await.expect("req rest");
		// Reply with the given code; bound addr 0.0.0.0:0.
		sock.write_all(&[0x05, reply_code, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
			.await
			.expect("reply");
		if reply_code == 0 {
			// Echo one line so the test can confirm the tunnel works.
			let mut buf = [0u8; 4];
			if sock.read_exact(&mut buf).await.is_ok() {
				let _ = sock.write_all(&buf).await;
			}
		}
	});
	addr
}

#[tokio::test]
async fn socks5_connect_tunnels_to_target() {
	let proxy = mock_socks_proxy(0).await;
	let mut stream = relay_connect("mail.example.org", 25, Some(&proxy))
		.await
		.expect("relay via socks");
	stream.write_all(b"ping").await.expect("write");
	let mut echo = [0u8; 4];
	stream.read_exact(&mut echo).await.expect("read echo");
	assert_eq!(&echo, b"ping");
}

#[tokio::test]
async fn socks5_connect_surfaces_proxy_failure() {
	// Reply code 5 == connection refused by the proxy.
	let proxy = mock_socks_proxy(5).await;
	let result = relay_connect("mail.example.org", 25, Some(&proxy)).await;
	assert!(matches!(result, Err(DeliveryError::Transient(_))));
}

#[tokio::test]
async fn direct_relay_connect_refused_is_transient() {
	// Nothing listening on this port: a transient connect error.
	let result = relay_connect("127.0.0.1", 1, None).await;
	assert!(matches!(result, Err(DeliveryError::Transient(_))));
}
