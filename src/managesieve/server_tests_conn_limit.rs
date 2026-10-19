//! One client address cannot hold more connections than its cap, and a
//! connection that ends gives its place back.

use super::*;
use crate::net::conn_limit::test_support::{connect, connect_when_a_place_frees};

async fn listening(per_ip: usize, listener_cap: usize) -> std::net::SocketAddr {
	let dir = tempfile::tempdir().expect("tempdir");
	let directory = DirectoryHandle::new(crate::smtp::directory::Directory::new(
		["example.org".to_string()],
		[("alice@example.org".to_string(), "alice".to_string())],
	));
	let (acceptor, _cert) = crate::tls::test_support::acceptor_and_cert();
	let server = Server::new(dir.keep(), directory, acceptor)
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
	assert_eq!(
		connect(addr).await.refusal(),
		Some("BYE \"too many connections from your address\"\r\n")
	);
}

#[tokio::test]
async fn a_place_is_given_back_when_the_connection_ends() {
	let addr = listening(1, 100).await;
	let held = connect(addr).await;
	assert!(held.refusal().is_none());
	assert!(connect(addr).await.refusal().is_some());
	drop(held);
	assert!(connect_when_a_place_frees(addr).await.refusal().is_none());
}

#[tokio::test]
async fn a_full_listener_says_so_even_to_a_new_client() {
	let addr = listening(10, 1).await;
	let _held = connect(addr).await;
	assert_eq!(
		connect(addr).await.refusal(),
		Some("BYE \"too many connections, try again later\"\r\n")
	);
}

#[test]
fn the_default_cap_per_client_can_act_before_the_listener_is_full() {
	let dir = tempfile::tempdir().expect("tempdir");
	let directory = DirectoryHandle::new(crate::smtp::directory::Directory::new(
		["example.org".to_string()],
		[("alice@example.org".to_string(), "alice".to_string())],
	));
	let (acceptor, _cert) = crate::tls::test_support::acceptor_and_cert();
	let server = Server::new(dir.path().to_path_buf(), directory, acceptor);
	assert!(
		server.max_per_ip < server.max_connections,
		"a per-client cap of {} cannot stop one client from filling a listener of {}",
		server.max_per_ip,
		server.max_connections
	);
}
