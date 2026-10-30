//! A fresh production STARTTLS listener and isolated script store per test.

use std::net::SocketAddr;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use epistle::managesieve::server::Server;
use tokio::io::AsyncRead;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;

pub use super::wire::*;

pub struct Harness {
	pub addr: SocketAddr,
	pub data: tempfile::TempDir,
	connector: TlsConnector,
	_task: AbortOnDrop,
}

impl Harness {
	pub async fn start(configure: impl FnOnce(Server) -> Server) -> Self {
		let (acceptor, connector, directory) = fixtures();
		let worktree = std::env::current_dir().expect("worktree directory");
		let data = tempfile::tempdir_in(worktree).expect("isolated script store");
		for account in ["tester", "victim"] {
			std::fs::create_dir_all(data.path().join("accounts").join(account))
				.expect("account directory");
		}
		let server = configure(Server::new(data.path().to_path_buf(), directory, acceptor));
		let listener = TcpListener::bind("127.0.0.1:0")
			.await
			.expect("bind ManageSieve");
		let addr = listener.local_addr().expect("listener address");
		let task = tokio::spawn(Arc::new(server).serve(listener));
		Self {
			addr,
			data,
			connector,
			_task: AbortOnDrop(task.abort_handle()),
		}
	}

	pub async fn connect(&self) -> TcpStream {
		let mut client = timeout(IO_DEADLINE, TcpStream::connect(self.addr))
			.await
			.expect("connect deadline")
			.expect("connect ManageSieve");
		client.set_nodelay(true).expect("disable Nagle");
		greeting(&mut client, false).await;
		client
	}

	pub async fn upgrade(&self, tcp: TcpStream) -> std::io::Result<Tls> {
		let name = ServerName::try_from("mail.epistle.test").expect("server name");
		timeout(IO_DEADLINE, self.connector.connect(name, tcp))
			.await
			.expect("TLS deadline")
	}

	pub async fn encrypted(&self) -> Tls {
		let mut client = self.connect().await;
		send(&mut client, b"STARTTLS\r\n").await;
		expect(&mut client, "OK \"Begin TLS negotiation now.\"\r\n").await;
		let mut client = self.upgrade(client).await.expect("TLS handshake");
		greeting(&mut client, true).await;
		client
	}

	pub async fn login(&self, account: &str) -> Tls {
		let mut client = self.encrypted().await;
		send(&mut client, authentication(account, &PASSWORD).as_bytes()).await;
		expect(&mut client, "OK \"Authenticated.\"\r\n").await;
		client
	}

	pub async fn healthy(&self) {
		let mut client = self.connect().await;
		send(&mut client, b"NOOP \"alive\"\r\n").await;
		expect(&mut client, "OK \"alive\"\r\n").await;
		logout(&mut client).await;
	}
}

pub fn authentication(account: &str, password: &str) -> String {
	let plain = B64.encode(format!("\0{account}\0{password}"));
	format!("AUTHENTICATE \"PLAIN\" \"{plain}\"\r\n")
}

pub async fn greeting<S: AsyncRead + Unpin>(client: &mut S, tls: bool) {
	expect(client, "\"IMPLEMENTATION\" \"epistle\"\r\n").await;
	let extensions = epistle::sieve::EXTENSIONS;
	expect(client, &format!("\"SIEVE\" \"{extensions}\"\r\n")).await;
	expect(client, "\"VERSION\" \"1.0\"\r\n").await;
	expect(
		client,
		if tls {
			"\"SASL\" \"PLAIN\"\r\n"
		} else {
			"\"STARTTLS\"\r\n"
		},
	)
	.await;
	expect(client, "OK \"ManageSieve ready.\"\r\n").await;
}

pub async fn logout<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(client: &mut S) {
	send(client, b"LOGOUT\r\n").await;
	expect(client, "BYE \"Goodbye.\"\r\n").await;
	closed(client).await;
}

pub async fn put(client: &mut Tls, name: &str, script: &str) {
	send(
		client,
		format!("PUTSCRIPT \"{name}\" {{{}+}}\r\n{script}\r\n", script.len()).as_bytes(),
	)
	.await;
}

pub async fn timed_out<S: AsyncRead + Unpin>(client: &mut S) {
	match line(client).await {
		Ok(None) => {}
		Err(e) if is_close(&e) => {}
		Ok(Some(reply)) => {
			assert!(
				matches!(
					reply.as_str(),
					"BYE \"Pre-authentication timeout.\"\r\n" | "BYE \"read timeout\"\r\n"
				),
				"{reply:?}"
			);
			closed(client).await;
		}
		other => panic!("expected timeout close, got {other:?}"),
	}
}
