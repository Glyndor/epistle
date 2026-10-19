use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test(start_paused = true)]
async fn connection_timeout_covers_stalled_tls_handshake() {
	let (tls, _) = crate::tls::test_support::acceptor_and_cert();
	let (mut client, server) = tokio::io::duplex(64);
	// Tests bypass the listener and hold an admit guard by hand.
	let admission = crate::net::conn_limit::Admission::new(100, 100);
	let peer: std::net::SocketAddr = "127.0.0.1:1".parse().expect("peer");
	let admitted = admission
		.admit(peer.ip())
		.expect("loopback under the cap of 100");
	let connection = connection(server, tls, Router::new(), admitted);
	tokio::pin!(connection);
	assert!(
		std::future::poll_fn(|cx| std::task::Poll::Ready(
			connection.as_mut().poll(cx).is_pending()
		))
		.await
	);
	tokio::time::advance(Duration::from_secs(29)).await;
	assert!(
		std::future::poll_fn(|cx| std::task::Poll::Ready(
			connection.as_mut().poll(cx).is_pending()
		))
		.await
	);
	client
		.write_all(&[22])
		.await
		.expect("open just before deadline");
	tokio::time::advance(Duration::from_secs(1)).await;
	assert!(
		std::future::poll_fn(|cx| std::task::Poll::Ready(connection.as_mut().poll(cx).is_ready()))
			.await,
		"connection must expire at 30 seconds"
	);
	let mut byte = [0];
	assert_eq!(client.read(&mut byte).await.expect("closed stream"), 0);
}
