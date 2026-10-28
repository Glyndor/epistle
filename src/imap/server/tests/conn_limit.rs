//! One client address cannot hold more connections than its cap, and a
//! connection that ends gives its place back.

use super::*;
use crate::net::conn_limit::test_support::{Outcome, connect, connect_when_a_place_frees};
use tokio::net::TcpListener;

async fn listening(per_ip: usize, listener_cap: usize) -> std::net::SocketAddr {
	let dir = tempfile::tempdir().expect("tempdir");
	let (acceptor, _cert) = crate::tls::test_support::acceptor_and_cert();
	let server = Server::new(
		"mail.example.org",
		dir.keep(),
		super::base::directory(),
		acceptor,
		TlsMode::StartTls,
	)
	.with_max_connections(listener_cap)
	.with_max_connections_per_ip(per_ip);
	let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
	let addr = listener.local_addr().expect("addr");
	tokio::spawn(Arc::new(server).serve(listener));
	addr
}

#[tokio::test]
async fn a_client_over_its_cap_gets_a_bye_and_a_close() {
	let addr = listening(2, 100).await;
	let first = connect(addr).await;
	let second = connect(addr).await;
	assert!(first.refusal().is_none() && second.refusal().is_none());
	let third = connect(addr).await;
	assert_eq!(
		third.refusal(),
		Some("* BYE too many connections from your address\r\n")
	);
	let Outcome::Admitted { greeting, .. } = &first else {
		panic!("the first connection was refused");
	};
	assert!(greeting.starts_with("* OK"), "{greeting}");
}

#[tokio::test]
async fn a_place_is_given_back_when_the_connection_ends() {
	let addr = listening(1, 100).await;
	let held = connect(addr).await;
	assert!(held.refusal().is_none());
	assert!(connect(addr).await.refusal().is_some());
	drop(held);
	let again = connect_when_a_place_frees(addr).await;
	assert!(again.refusal().is_none());
}

#[tokio::test]
async fn a_full_listener_says_so_even_to_a_new_client() {
	let addr = listening(10, 1).await;
	let _held = connect(addr).await;
	assert_eq!(
		connect(addr).await.refusal(),
		Some("* BYE too many connections, try again later\r\n")
	);
}
