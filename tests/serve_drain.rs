//! SIGTERM drains the real server: `epistle local` (which runs the same
//! `serve` as production) is stopped while an SMTP client is in the middle
//! of DATA and an IMAP client sits idle. The message must still be accepted,
//! both clients must be told goodbye, and the process must exit cleanly
//! before the 30 s `stop_grace_period` podup gives the `mail` service.
//!
//! The message is submitted on the implicit-TLS submission port with AUTH as
//! the account `epistle local` creates, so no SPF lookup (and no DNS at all)
//! decides the outcome: an unauthenticated sender on port 25 made the test
//! depend on the runner's resolver, which answered `451 4.4.3` in CI.

use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

#[allow(dead_code)]
mod common;
use common::{BIND_DEADLINE, Child, pick_port_base, redact_password, wait_for_bind};

/// Read lines until one starts with `prefix`, failing after 10 s.
fn line_starting(reader: &mut impl BufRead, prefix: &str) -> String {
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

/// The submissions port (465) of `epistle local`, over TLS trusting the
/// `cert.pem` the run generated.
fn submissions(port: u16, cert: &Path) -> BufReader<StreamOwned<ClientConnection, TcpStream>> {
	let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
	let mut roots = RootCertStore::empty();
	for certificate in CertificateDer::pem_file_iter(cert).expect("read cert.pem") {
		roots
			.add(certificate.expect("parse cert.pem"))
			.expect("trust cert.pem");
	}
	let config = ClientConfig::builder()
		.with_root_certificates(roots)
		.with_no_client_auth();
	let name: ServerName<'static> = "mail.local.test".try_into().unwrap();
	let connection = ClientConnection::new(Arc::new(config), name).unwrap();
	let (_, stream) = connect(port);
	BufReader::new(StreamOwned::new(connection, stream))
}

/// The password `epistle local` printed on its first run.
fn printed_password(child: &Child) -> String {
	let deadline = Instant::now() + BIND_DEADLINE;
	loop {
		let stderr = String::from_utf8_lossy(&child.stderr_snapshot()).into_owned();
		if let Some(password) = stderr
			.lines()
			.find_map(|line| line.trim().strip_prefix("password:"))
			.and_then(|rest| rest.split_whitespace().next())
		{
			return password.to_string();
		}
		assert!(Instant::now() < deadline, "no password in the banner");
		std::thread::sleep(Duration::from_millis(20));
	}
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
	let smtp = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), base + 465);
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

	let password = printed_password(&child);
	let mut smtp = submissions(base + 465, &dir.path().join("cert.pem"));
	line_starting(&mut smtp, "220 ");
	let plain = base64::engine::general_purpose::STANDARD.encode(format!("\0user\0{password}"));
	for (command, reply) in [
		("EHLO client.test\r\n".to_string(), "250 "),
		(format!("AUTH PLAIN {plain}\r\n"), "235 "),
		("MAIL FROM:<user@local.test>\r\n".to_string(), "250 "),
		("RCPT TO:<user@local.test>\r\n".to_string(), "250 "),
		("DATA\r\n".to_string(), "354 "),
	] {
		smtp.get_mut().write_all(command.as_bytes()).unwrap();
		smtp.get_mut().flush().unwrap();
		line_starting(&mut smtp, reply);
	}

	let pid = child.proc.id() as i32;
	// SAFETY: kill only sends a signal to the child this test spawned.
	assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);
	std::thread::sleep(Duration::from_millis(300));

	let bye = line_starting(&mut imap_reader, "* BYE");
	assert!(bye.contains("shutting down"), "{bye}");

	smtp.get_mut()
		.write_all(b"From: <user@local.test>\r\nTo: <user@local.test>\r\nSubject: drain\r\n\r\nsent while the server stops\r\n.\r\n")
		.unwrap();
	smtp.get_mut().flush().unwrap();
	let accepted = line_starting(&mut smtp, "250 ");
	assert!(accepted.starts_with("250 "), "{accepted}");
	let goodbye = line_starting(&mut smtp, "421 ");
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
