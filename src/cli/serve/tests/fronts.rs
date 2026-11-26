//! `serve --fronts`: the listeners that serve the API are Unix sockets in the
//! directories of the fronts, and bind no TCP port.

use super::*;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// `GET /healthz` on `socket`, with the front's header unless `peer` is false.
async fn healthz(socket: &std::path::Path, peer: bool) -> String {
	let mut stream = None;
	for _ in 0..200 {
		if let Ok(connected) = UnixStream::connect(socket).await {
			stream = Some(connected);
			break;
		}
		tokio::time::sleep(Duration::from_millis(40)).await;
	}
	let mut stream = stream.expect("the socket came up");
	let header = if peer {
		"X-Epistle-Peer: 127.0.0.1\r\n"
	} else {
		""
	};
	stream
		.write_all(
			format!("GET /healthz HTTP/1.1\r\nHost: x\r\n{header}Connection: close\r\n\r\n")
				.as_bytes(),
		)
		.await
		.expect("write");
	let mut answer = String::new();
	stream.read_to_string(&mut answer).await.expect("read");
	answer
}

#[tokio::test]
async fn serve_with_fronts_puts_each_api_listener_on_its_socket() {
	let dir = tempfile::tempdir().expect("tempdir");
	let jmap = crate::test_support::fixtures::free_port();
	let api = crate::test_support::fixtures::free_port();
	let hash = format!("sha256:{}", "ab".repeat(32));
	let mut config: Config = toml::from_str(&format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\ndomains = [\"example.org\"]\n\
		 [api]\ntoken_hash = \"{hash}\"\n\
		 [[listeners]]\nkind = \"api\"\naddr = \"127.0.0.1\"\nport = {api}\n\
		 [[listeners]]\nkind = \"jmap\"\naddr = \"127.0.0.1\"\nport = {jmap}\n",
		dir.path().join("data").display()
	))
	.expect("config");
	config.tls = None;
	let data_dir = config.data_dir.clone();
	let server = tokio::spawn(super::super::serve(config, ServeRole::All, None, true));
	for kind in [ListenerKind::Api, ListenerKind::Jmap] {
		let socket = crate::api::front_socket::path(&data_dir, kind);
		assert!(socket.starts_with(dir.path().join("fronts")), "{socket:?}");
		let answer = healthz(&socket, true).await;
		assert!(answer.starts_with("HTTP/1.1 200"), "{kind:?}: {answer}");
		// Whatever is on the socket and is no front is refused.
		let answer = healthz(&socket, false).await;
		assert!(answer.starts_with("HTTP/1.1 400"), "{kind:?}: {answer}");
	}
	// No TCP port was bound for them.
	for port in [api, jmap] {
		assert!(
			tokio::net::TcpStream::connect(("127.0.0.1", port))
				.await
				.is_err(),
			"{port} answers on TCP"
		);
	}
	server.abort();
}
