//! A fresh production implicit TLS listener and isolated mail store per test.

use std::net::SocketAddr;
use std::sync::Arc;

use epistle::pop3::server::Server;
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
		let data = tempfile::tempdir_in(worktree).expect("isolated mail store");
		for account in ["tester", "victim"] {
			std::fs::create_dir_all(data.path().join("accounts").join(account).join("new"))
				.expect("account inbox");
		}
		let server = configure(Server::new(data.path().to_path_buf(), directory, acceptor));
		let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind POP3");
		let addr = listener.local_addr().expect("listener address");
		let task = tokio::spawn(Arc::new(server).serve(listener));
		Self {
			addr,
			data,
			connector,
			_task: AbortOnDrop(task.abort_handle()),
		}
	}

	pub async fn tcp(&self) -> TcpStream {
		let client = timeout(IO_DEADLINE, TcpStream::connect(self.addr))
			.await
			.expect("connect deadline")
			.expect("connect POP3");
		client.set_nodelay(true).expect("disable Nagle");
		client
	}

	pub async fn connect(&self) -> Tls {
		let name = ServerName::try_from("mail.epistle.test").expect("server name");
		let mut client = timeout(IO_DEADLINE, self.connector.connect(name, self.tcp().await))
			.await
			.expect("TLS deadline")
			.expect("TLS handshake");
		expect(&mut client, "+OK POP3 ready\r\n").await;
		client
	}

	pub async fn login(&self, account: &str, count: usize) -> Tls {
		let mut client = self.connect().await;
		send(&mut client, format!("USER {account}\r\n").as_bytes()).await;
		expect(&mut client, "+OK send PASS\r\n").await;
		send(&mut client, format!("PASS {PASSWORD}\r\n").as_bytes()).await;
		expect(
			&mut client,
			&format!("+OK mailbox ready, {count} messages\r\n"),
		)
		.await;
		client
	}

	pub fn seed(&self, account: &str, uid: &str, content: &[u8]) -> std::path::PathBuf {
		let path = self
			.data
			.path()
			.join("accounts")
			.join(account)
			.join("new")
			.join(format!("{uid}.eml"));
		std::fs::write(&path, content).expect("seed message");
		path
	}

	/// Probe the same listener with a new TLS connection after each attack.
	pub async fn healthy(&self) {
		let mut client = self.connect().await;
		send(&mut client, b"CAPA\r\n").await;
		for reply in [
			"+OK capability list follows\r\n",
			"USER\r\n",
			"UIDL\r\n",
			"TOP\r\n",
			"SASL PLAIN\r\n",
			".\r\n",
		] {
			expect(&mut client, reply).await;
		}
		quit(&mut client).await;
	}
}

pub async fn quit(client: &mut Tls) {
	send(client, b"QUIT\r\n").await;
	expect(client, "+OK bye\r\n").await;
	closed(client).await;
}
