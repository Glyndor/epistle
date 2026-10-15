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

#[test]
fn serve_emits_single_signature_dkim_warning_at_startup() {
	// The DKIM single-signature warning is the very first thing `serve`
	// does after loading the config — before listeners bind, before the
	// AccountStore opens. Empty listener list returns early after the
	// no-listeners notice (which is `eprintln!`, not `tracing`), so a
	// captured event with `remedy = "epistle dkim-keygen --rsa"` proves
	// the call site is wired to the shared helper.
	//
	// `run_with_capture` requires a sync closure, and the surrounding
	// test framework may already be inside a tokio runtime, so we drive
	// `serve::serve` from a fresh current-thread runtime here.
	use super::super::tracing_capture::run_with_capture;
	use tracing::Level;

	let dir = tempfile::tempdir().expect("tempdir");
	let mut config: Config = toml::from_str(&format!(
		"
hostname = \"mail.example.org\"
data_dir = {:?}
domains = [\"example.org\"]

[dkim]
selector = \"mail\"
key_file = \"/etc/mail/dkim.pem\"
",
		dir.path()
	))
	.expect("config");
	// No listeners: serve returns Ok(()) after the warning is logged.
	config.listeners.clear();

	let events = run_with_capture(|| {
		let runtime = tokio::runtime::Builder::new_current_thread()
			.enable_all()
			.build()
			.expect("runtime");
		let _ = runtime.block_on(serve(config));
	});
	let warning = events
		.iter()
		.find(|e| e.level == Level::WARN && e.fields.contains_key("remedy"))
		.expect("expected a tracing::warn! with the remedy field");
	assert_eq!(
		warning.fields.get("remedy").map(String::as_str),
		Some("epistle dkim-keygen --rsa"),
		"remedy field must name the keygen command"
	);
	let message = warning
		.fields
		.get("message")
		.expect("message field")
		.as_str();
	assert!(
		message.contains("signs with one key only"),
		"warning message must use the shared helper text: {message}"
	);
	assert!(
		message.contains(crate::config::DKIM_RSA_REQUIRED_FROM),
		"warning message must name the version that flips to refusal: {message}"
	);
}

#[test]
fn serve_is_silent_on_dkim_when_both_rsa_fields_are_set() {
	// Symmetric to the previous test: a fully-configured DKIM section
	// must not log the single-signature warning. The no-listeners notice
	// is `eprintln!`, so the captured events list must not contain any
	// event with the `remedy` field.
	use super::super::tracing_capture::run_with_capture;

	let dir = tempfile::tempdir().expect("tempdir");
	let mut config: Config = toml::from_str(&format!(
		"
hostname = \"mail.example.org\"
data_dir = {:?}
domains = [\"example.org\"]

[dkim]
selector = \"mail\"
key_file = \"/etc/mail/dkim.pem\"
rsa_selector = \"rsa1\"
rsa_key_file = \"/etc/mail/rsa.pem\"
",
		dir.path()
	))
	.expect("config");
	config.listeners.clear();

	let events = run_with_capture(|| {
		let runtime = tokio::runtime::Builder::new_current_thread()
			.enable_all()
			.build()
			.expect("runtime");
		let _ = runtime.block_on(serve(config));
	});
	assert!(
		events.iter().all(|e| !e.fields.contains_key("remedy")),
		"both RSA fields set: serve must not log the single-signature warning, got {events:?}"
	);
}

/// POST `body` to `path` on the API at `port` with the fixture token and
/// return the HTTP status code. Retries the connect while `serve` binds.
async fn api_post_status(port: u16, path: &str, body: &[u8]) -> u16 {
	let mut stream = None;
	for _ in 0..100 {
		match tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await {
			Ok(connected) => {
				stream = Some(connected);
				break;
			}
			Err(_) => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
		}
	}
	let mut stream = stream.expect("the API listener comes up");
	let head = format!(
		"POST {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\n\
Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
		crate::test_fixtures::api_token(),
		body.len()
	);
	stream.write_all(head.as_bytes()).await.expect("head");
	let _ = stream.write_all(body).await;
	let mut response = Vec::new();
	let _ = stream.read_to_end(&mut response).await;
	let status = String::from_utf8_lossy(&response[..response.len().min(12)]).into_owned();
	status
		.strip_prefix("HTTP/1.1 ")
		.and_then(|code| code.parse().ok())
		.expect("an HTTP status line")
}

#[tokio::test]
async fn serve_applies_max_message_size_to_the_api() {
	// The configured cap must reach the REST send body limit, not only the
	// SMTP listeners: an 8 KiB body under a 4 KiB cap is refused with 413
	// before it is parsed.
	let probe = TcpListener::bind((IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
		.await
		.expect("probe bind");
	let port = probe.local_addr().expect("addr").port();
	drop(probe);
	let dir = tempfile::tempdir().expect("tempdir");
	let listener: Listener =
		toml::from_str(&format!("kind = \"api\"\nport = {port}")).expect("listener config");
	let mut config = test_config(dir.path(), vec![listener]);
	config.max_message_size = Some(4096);
	config.api = Some(
		toml::from_str(&format!(
			"token_hash = \"{}\"",
			crate::smtp::auth::tests::hash(crate::test_fixtures::api_token())
		))
		.expect("api config"),
	);
	let server = tokio::spawn(serve(config));
	let body = format!("{{\"pad\":\"{}\"}}", "x".repeat(8 * 1024));
	let status = api_post_status(port, "/api/v1/send", body.as_bytes()).await;
	server.abort();
	assert_eq!(status, 413, "the API body limit follows max_message_size");
}

#[tokio::test(start_paused = true)]
async fn serve_applies_the_rate_floor_to_smtp() {
	// A floor no client can meet after a one-second grace: the listener
	// `serve` builds cuts a dripped BDAT chunk then, not after the
	// built-in 120 s.
	let probe = TcpListener::bind((IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
		.await
		.expect("probe bind");
	let port = probe.local_addr().expect("addr").port();
	drop(probe);
	let dir = tempfile::tempdir().expect("tempdir");
	let listener: Listener = toml::from_str(&format!(
		"kind = \"smtp\"\naddr = \"127.0.0.1\"\nport = {port}"
	))
	.expect("listener config");
	let mut config = test_config(dir.path(), vec![listener]);
	config.min_data_rate = Some(1024 * 1024 * 1024);
	config.data_rate_grace = Some(1);
	let server = tokio::spawn(serve(config));
	let mut stream = None;
	for _ in 0..100 {
		match tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await {
			Ok(connected) => {
				stream = Some(connected);
				break;
			}
			Err(_) => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
		}
	}
	let mut stream = stream.expect("the SMTP listener comes up");
	stream
		.write_all(b"EHLO client.example.org\r\nBDAT 4096\r\n")
		.await
		.expect("write");
	let started = tokio::time::Instant::now();
	let mut output = Vec::new();
	let _ = stream.read_to_end(&mut output).await;
	let elapsed = started.elapsed();
	server.abort();
	let output = String::from_utf8_lossy(&output);
	assert!(
		output.ends_with("421 4.4.2 transfer too slow, closing connection\r\n"),
		"the configured floor cuts the chunk: {output}"
	);
	assert!(
		elapsed < std::time::Duration::from_secs(5),
		"after the configured grace, not at {elapsed:?}"
	);
}
