//! Tests for `serve`. In a sibling file like every other module here, and
//! because `serve.rs` is at the per-file line ceiling: an inline block
//! counts against the same limit as the code it tests.

use super::*;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

use crate::config::Listener;
use crate::smtp::sink::MemorySink;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn test_config(data_dir: &Path, listeners: Vec<Listener>) -> Config {
	let toml = format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\n",
		data_dir.display()
	);
	let mut config: Config = toml::from_str(&toml).expect("base config");
	config.listeners = listeners;
	config
}

#[test]
fn run_with_no_listeners_exits_cleanly() {
	let dir = tempfile::tempdir().expect("tempdir");
	assert_eq!(run(test_config(dir.path(), vec![])), ExitCode::SUCCESS);
}

#[tokio::test]
async fn serve_binds_and_answers() {
	// Port 0 lets the OS pick a free port; we then talk to it.
	let listener = TcpListener::bind((IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
		.await
		.expect("bind");
	let addr = listener.local_addr().expect("addr");

	let sink: Arc<dyn MessageSink> = Arc::new(MemorySink::new());
	let server = Arc::new(Server::new("mail.example.org", sink));
	let task = tokio::spawn(server.serve(listener));

	let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
	let mut buffer = [0u8; 64];
	let read = client.read(&mut buffer).await.expect("greeting");
	assert!(String::from_utf8_lossy(&buffer[..read]).starts_with("220 "));
	client.write_all(b"QUIT\r\n").await.expect("quit");
	task.abort();
}

#[tokio::test]
async fn serve_fails_on_unbindable_address() {
	// Two listeners on the same port: the second bind must fail.
	let probe = TcpListener::bind((IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
		.await
		.expect("probe bind");
	let port = probe.local_addr().expect("addr").port();

	let dir = tempfile::tempdir().expect("tempdir");
	let listener: Listener =
		toml::from_str(&format!("kind = \"smtp\"\nport = {port}")).expect("listener config");
	let config = test_config(dir.path(), vec![listener]);
	assert!(serve(config).await.is_err());
}

#[tokio::test]
async fn serve_fails_on_unwritable_data_dir() {
	let listener: Listener = toml::from_str("kind = \"smtp\"\nport = 0").expect("listener");
	let config = test_config(Path::new("/proc/no-such-dir"), vec![listener]);
	assert!(serve(config).await.is_err());
}
