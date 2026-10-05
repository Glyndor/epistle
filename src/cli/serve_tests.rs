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
