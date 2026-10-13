//! SIGTERM drains the real server: `epistle local` (which runs the same
//! `serve` as production) is stopped while an SMTP client is in the middle
//! of DATA and an IMAP client sits idle. The message must still be accepted,
//! both clients must be told goodbye, and the process must exit cleanly
//! before the 30 s `stop_grace_period` podup gives the `mail` service.

use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

#[allow(dead_code)]
mod common;
use common::{BIND_DEADLINE, Child, pick_port_base, redact_password, wait_for_bind};

/// Read lines until one starts with `prefix`, failing after 10 s.
fn line_starting(reader: &mut BufReader<TcpStream>, prefix: &str) -> String {
	let mut seen = String::new();
	loop {
		let mut line = String::new();
		let read = reader
			.read_line(&mut line)
			.unwrap_or_else(|error| panic!("waiting for {prefix:?}: {error}; got {seen:?}"));
		assert!(read > 0, "closed before {prefix:?}; got {seen:?}");
		seen.push_str(&line);
		if line.starts_with(prefix) {
			return line;
		}
	}
}

fn connect(port: u16) -> (BufReader<TcpStream>, TcpStream) {
	let stream = TcpStream::connect(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port))
		.expect("connect");
	stream
		.set_read_timeout(Some(Duration::from_secs(10)))
		.unwrap();
	(BufReader::new(stream.try_clone().unwrap()), stream)
}

#[test]
fn sigterm_lets_an_open_transaction_finish_and_says_goodbye() {
	let dir = tempfile::tempdir().unwrap();
	let base = pick_port_base();
	let base_arg = base.to_string();
	let dir_arg = dir.path().to_str().unwrap().to_string();
	let mut child = Child::spawn(
		&["local", "--dir", &dir_arg, "--port-base", &base_arg],
		dir.path(),
	);
	let smtp = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), base + 25);
	let imap = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), base + 143);
	for addr in [smtp, imap] {
		wait_for_bind(
			addr,
			Instant::now() + BIND_DEADLINE,
			"waiting for the listeners",
			&mut child,
		)
		.unwrap_or_else(|error| panic!("{error}"));
	}

	let (mut imap_reader, _imap_writer) = connect(base + 143);
	line_starting(&mut imap_reader, "* OK");

	let (mut reader, mut writer) = connect(base + 25);
	line_starting(&mut reader, "220 ");
	for (command, reply) in [
		("EHLO client.test\r\n", "250 "),
		("MAIL FROM:<sender@client.test>\r\n", "250 "),
		("RCPT TO:<user@local.test>\r\n", "250 "),
		("DATA\r\n", "354 "),
	] {
		writer.write_all(command.as_bytes()).unwrap();
		line_starting(&mut reader, reply);
	}

	let pid = child.proc.id() as i32;
	// SAFETY: kill only sends a signal to the child this test spawned.
	assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);
	std::thread::sleep(Duration::from_millis(300));

	let bye = line_starting(&mut imap_reader, "* BYE");
	assert!(bye.contains("shutting down"), "{bye}");

	writer
		.write_all(b"Subject: drain\r\n\r\nsent while the server stops\r\n.\r\n")
		.unwrap();
	let accepted = line_starting(&mut reader, "250 ");
	assert!(accepted.starts_with("250 "), "{accepted}");
	let goodbye = line_starting(&mut reader, "421 ");
	assert!(goodbye.contains("4.3.2"), "{goodbye}");

	let deadline = Instant::now() + Duration::from_secs(25);
	let status = loop {
		if let Some(status) = child.proc.try_wait().unwrap() {
			break status;
		}
		if Instant::now() >= deadline {
			let stderr = child.stderr_snapshot();
			panic!(
				"the server was still running 25 s after SIGTERM\nstderr:\n{}",
				redact_password(&stderr)
			);
		}
		std::thread::sleep(Duration::from_millis(50));
	};
	assert!(
		status.success(),
		"the server exits cleanly after the drain: {status:?}"
	);
}
