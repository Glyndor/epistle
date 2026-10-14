use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

use super::probe::run_within;
use super::*;
use crate::cli::resource::test_config;

fn config(port: u16, extra: &str) -> (tempfile::TempDir, tempfile::NamedTempFile, Config) {
	let (dir, file) = test_config(&format!(
		"\n[[transport]]\nkind = 'relay'\nhost = '127.0.0.1'\nport = {port}\n{extra}"
	));
	let config = Config::load(file.path()).unwrap();
	(dir, file, config)
}

/// A plain smarthost that greets, answers EHLO and QUIT and records commands.
fn smarthost() -> (u16, std::thread::JoinHandle<Vec<String>>) {
	let runtime = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()
		.unwrap();
	let listener = runtime.block_on(TcpListener::bind("127.0.0.1:0")).unwrap();
	let port = listener.local_addr().unwrap().port();
	let handle = std::thread::spawn(move || {
		runtime.block_on(async {
			let (stream, _) = listener.accept().await.unwrap();
			let (read, mut write) = stream.into_split();
			let mut lines = BufReader::new(read).lines();
			write.write_all(b"220 smarthost ready\r\n").await.unwrap();
			let mut seen = Vec::new();
			while let Ok(Some(line)) = lines.next_line().await {
				let reply: &[u8] = if line.starts_with("EHLO") {
					b"250 smarthost\r\n"
				} else {
					b"221 bye\r\n"
				};
				seen.push(line);
				write.write_all(reply).await.unwrap();
			}
			seen
		})
	});
	(port, handle)
}

#[test]
fn test_reports_each_step_and_sends_no_mail() {
	let (port, server) = smarthost();
	let (_dir, _file, config) = config(port, "");
	let (mut out, mut status) = (Vec::new(), Vec::new());
	let code = run_within(
		&config,
		&Target::default(),
		Duration::from_secs(5),
		&mut out,
		&mut status,
	)
	.unwrap();
	assert_eq!(code, ExitCode::SUCCESS);
	assert_eq!(
		String::from_utf8(out).unwrap(),
		"ok\tconnect\nok\tEHLO\nok\tQUIT\n"
	);
	assert_eq!(
		String::from_utf8(status).unwrap(),
		format!("relay test passed for 127.0.0.1:{port}; no mail was sent\n")
	);
	assert_eq!(
		server.join().unwrap(),
		["EHLO mail.example.org", "QUIT"],
		"the test must send nothing but EHLO and QUIT"
	);
}

#[test]
fn test_fails_with_the_refused_connection() {
	let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
	let port = listener.local_addr().unwrap().port();
	drop(listener);
	let (_dir, _file, config) = config(port, "");
	let error = run_within(
		&config,
		&Target::default(),
		Duration::from_secs(5),
		&mut Vec::new(),
		&mut Vec::new(),
	)
	.unwrap_err();
	assert!(
		error.as_ref().starts_with(&format!(
			"relay test failed for 127.0.0.1:{port}: relay connect:"
		)),
		"{error}"
	);
}

#[test]
fn test_gives_up_when_the_smarthost_never_greets() {
	let runtime = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()
		.unwrap();
	let listener = runtime.block_on(TcpListener::bind("127.0.0.1:0")).unwrap();
	let port = listener.local_addr().unwrap().port();
	let (_dir, _file, config) = config(port, "");
	let started = std::time::Instant::now();
	let error = run_within(
		&config,
		&Target::default(),
		Duration::from_millis(300),
		&mut Vec::new(),
		&mut Vec::new(),
	)
	.unwrap_err();
	assert_eq!(
		error.as_ref(),
		format!("relay test failed for 127.0.0.1:{port}: no answer within 0.3 s")
	);
	assert!(started.elapsed() < Duration::from_secs(5));
	drop(listener);
}

#[test]
fn test_names_the_missing_rule() {
	let (_dir, file) = test_config("");
	let config = Config::load(file.path()).unwrap();
	let error = run_within(
		&config,
		&Target {
			account: Some("alice".into()),
			domain: None,
		},
		Duration::from_secs(1),
		&mut Vec::new(),
		&mut Vec::new(),
	)
	.unwrap_err();
	assert_eq!(error.as_ref(), "no relay is configured for account alice");
}
