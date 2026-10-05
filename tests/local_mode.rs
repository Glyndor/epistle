//! `epistle local` end-to-end: spawn the real binary, wait for it to
//! bind every listener, then drive the protocols the harness exposes.
//!
//! The contract:
//!
//! - the server binds six listeners on `127.0.0.1` at
//!   `port-base + {25, 587, 465, 143, 993, 8025}`;
//! - the SMTP greeting advertises the harness hostname
//!   (`mail.local.test`);
//! - the IMAPS port accepts a TCP connection;
//! - nothing the operator asked for lands on stdout;
//! - killing the child leaves the marker file behind so a second run
//!   reuses the directory byte for byte.
//!
//! Every wait in this driver is a poll on a condition with a deadline;
//! nothing sleeps for synchronisation. The banner reader stops on the
//! `220 CRLF` terminator instead of waiting for a fixed buffer to fill,
//! the kill path uses `kill` then `wait` so a child that traps SIGTERM
//! still reaps promptly, and every retry is gated on the child's own
//! stderr naming `EADDRINUSE` rather than on the client's view of a
//! refused connect (which would also match a server that simply died).

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

mod common;
use common::{Child, is_eaddrinuse, pick_port_base, read_banner, redact_password, wait_for_bind};

/// Server name the harness exposes. Mirrors `HOSTNAME` in
/// `src/cli/local/mod.rs`; pinned here so a future rename breaks
/// the test rather than silently passing the TLS handshake against
/// the wrong name.
const TLS_SERVER_NAME: &str = "mail.local.test";

/// Read and write timeouts the TLS probe installs on the TCP socket
/// before driving the handshake. Without them a peer that accepts
/// the TCP connection and never answers blocks `read` / `write`
/// forever and the test harness cannot reap the child process;
/// setting SO_RCVTIMEO / SO_SNDTIMEO turns a stuck peer into a
/// `TimedOut` error the probe can name with the phase.
const TLS_PROBE_IO_TIMEOUT: Duration = Duration::from_secs(2);

/// Drive a real TLS 1.2+/1.3 client handshake against `stream` and
/// return the first protocol line the server emits through the
/// encrypted channel. The trust anchor is exactly the `cert.pem` the
/// run generated, so a TLS listener that finishes the handshake with
/// any other certificate is rejected. The server name is
/// `mail.local.test` (the harness `HOSTNAME`); the same constant is
/// used by the local-mode server, so a hostname mismatch would surface
/// as a TLS alert.
///
/// Time bound: each read and each write on the underlying `TcpStream`
/// is bounded by the socket-level `SO_RCVTIMEO` / `SO_SNDTIMEO`
/// timeouts (the [`TLS_PROBE_IO_TIMEOUT`] constant, currently 2 s).
/// The handshake loop is a `complete_io` per direction, and the
/// greeting read is one `read` per chunk; every one of those calls
/// returns `TimedOut` after the timeout, so a peer that accepts the
/// TCP connection and never answers any of them surfaces as an
/// `Err` carrying the phase (`handshake` or `greeting`) and the
/// port. The probe does NOT promise a total wall-clock bound: the
/// socket timeouts bound each blocking call individually, so a peer
/// that answers one byte at a time can hold the probe open across
/// many timeout windows. The hung-peer test
/// (`tls_probe_returns_timeout_error_against_hung_peer`) pins the
/// silent case with a 10 s watchdog that fails the test if the
/// probe has not returned by then.
fn probe_tls_real(stream: TcpStream, phase: &str, cert_pem_path: &Path) -> Result<String, String> {
	// Install the ring provider once. The runtime's serve path installs
	// the same provider on startup; a parallel `cargo test` run can
	// race the first installer, so wrap it in `Once`-equivalent. A
	// second install is a no-op (`install_default` returns Err for an
	// already-installed provider), so ignore the outcome.
	let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();

	let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert_pem_path)
		.map_err(|error| format!("{phase}: read {cert_pem_path:?}: {error:?}"))?
		.collect::<Result<_, _>>()
		.map_err(|error| format!("{phase}: parse {cert_pem_path:?}: {error:?}"))?;
	if certs.is_empty() {
		return Err(format!("{phase}: no certificates in {cert_pem_path:?}"));
	}
	let mut roots = RootCertStore::empty();
	roots
		.add(certs.into_iter().next().expect("non-empty checked above"))
		.map_err(|error| format!("{phase}: add trust anchor: {error:?}"))?;
	let config = ClientConfig::builder()
		.with_root_certificates(roots)
		.with_no_client_auth();
	let server_name: ServerName<'static> = TLS_SERVER_NAME
		.try_into()
		.map_err(|error| format!("{phase}: server name: {error:?}"))?;
	let conn = ClientConnection::new(Arc::new(config), server_name)
		.map_err(|error| format!("{phase}: build client connection: {error:?}"))?;
	// Install the read/write timeouts on the underlying TCP socket so
	// a peer that accepts the connection and never answers the
	// handshake surfaces as a `TimedOut` error rather than blocking
	// the test thread. The probe must always finish within
	// `TLS_PROBE_IO_TIMEOUT` per direction; the test pins that with a
	// hung-peer listener (see `tls_probe_returns_timeout_error_against_hung_peer`).
	stream
		.set_read_timeout(Some(TLS_PROBE_IO_TIMEOUT))
		.map_err(|error| format!("{phase}: set_read_timeout: {error:?}"))?;
	stream
		.set_write_timeout(Some(TLS_PROBE_IO_TIMEOUT))
		.map_err(|error| format!("{phase}: set_write_timeout: {error:?}"))?;
	let mut tls = StreamOwned::new(conn, stream);
	// Drive the handshake until completion by calling complete_io
	// through StreamOwned. We loop because each call may only flush
	// one direction; the handshake is finished when is_handshaking()
	// flips to false. The first call sends the ClientHello; subsequent
	// calls wait for the ServerHello / cert / Finished and verify.
	// A `TimedOut` here names the handshake phase so the operator sees
	// where the peer stopped answering.
	while tls.conn.is_handshaking() {
		match tls.conn.complete_io(&mut tls.sock) {
			Ok(_) => {}
			Err(error)
				if error.kind() == std::io::ErrorKind::WouldBlock
					|| error.kind() == std::io::ErrorKind::TimedOut =>
			{
				return Err(format!(
					"{phase}: TLS handshake did not complete within {TLS_PROBE_IO_TIMEOUT:?}"
				));
			}
			Err(error) => return Err(format!("{phase}: TLS handshake: {error:?}")),
		}
	}
	let mut buf = Vec::with_capacity(128);
	let mut chunk = [0u8; 128];
	loop {
		if buf.windows(2).any(|w| w == b"\r\n") {
			break;
		}
		if buf.len() >= 512 {
			return Err(format!(
				"{phase}: TLS greeting exceeded 512 bytes without CRLF; got {:?}",
				String::from_utf8_lossy(&buf)
			));
		}
		match std::io::Read::read(&mut tls, &mut chunk) {
			Ok(0) => {
				return Err(format!(
					"{phase}: TLS peer closed before greeting; got {:?}",
					String::from_utf8_lossy(&buf)
				));
			}
			Ok(n) => buf.extend_from_slice(&chunk[..n]),
			Err(error)
				if error.kind() == std::io::ErrorKind::WouldBlock
					|| error.kind() == std::io::ErrorKind::TimedOut =>
			{
				return Err(format!(
					"{phase}: TLS greeting did not arrive within {TLS_PROBE_IO_TIMEOUT:?}"
				));
			}
			Err(error) => return Err(format!("{phase}: read greeting: {error:?}")),
		}
	}
	String::from_utf8(buf).map_err(|error| format!("{phase}: greeting is not utf-8: {error:?}"))
}

/// Probe the plaintext SMTP port with the same real handshake the
/// implicit-TLS ports use. The handshake must FAIL: a plaintext
/// listener that returned a TLS-shaped response to the malformed
/// `ClientHello` would pass the probe, and the test pinning the failure
/// is what keeps the TLS probe honest.
fn probe_tls_real_must_fail(
	stream: TcpStream,
	phase: &str,
	cert_pem_path: &Path,
) -> Result<(), String> {
	let result = probe_tls_real(stream, phase, cert_pem_path);
	if result.is_ok() {
		return Err(format!(
			"{phase}: TLS handshake unexpectedly succeeded against a plaintext listener"
		));
	}
	Ok(())
}

/// Run one attempt. Returns `Ok(())` if everything passed; otherwise
/// an error message that names the phase and quotes the redacted
/// stderr. The retry loop reads it.
fn run_once(dir: &Path, port_base: u16) -> Result<(), String> {
	let port_base_str = port_base.to_string();
	let dir_str = dir.to_str().expect("utf-8 tempdir path").to_owned();
	let args = [
		"local",
		"--dir",
		dir_str.as_str(),
		"--port-base",
		port_base_str.as_str(),
	];
	let mut child = Child::spawn(&args, dir);

	let bind_deadline = Instant::now() + Duration::from_secs(10);
	let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
	let cert_pem_path = dir.join("cert.pem");

	// SMTP (25): the SMTP greeting is the strictest probe we have, so
	// it stays first. The banner must advertise the harness hostname
	// and start with `220 `, otherwise the listener could pass the
	// bind check without being SMTP.
	let smtp_addr = SocketAddr::new(loopback, port_base + 25);
	let mut smtp = wait_for_bind(
		smtp_addr,
		bind_deadline,
		"waiting for SMTP port",
		&mut child,
	)?;
	let banner = read_banner(
		&mut smtp,
		Instant::now() + Duration::from_secs(2),
		"reading the SMTP banner",
	)?;
	drop(smtp);
	let banner_text = String::from_utf8_lossy(&banner);

	if !banner_text.starts_with("220 ") {
		let (_stdout, stderr) = child.kill_and_drain(
			Instant::now() + Duration::from_secs(2),
			"reading the SMTP banner",
		)?;
		return Err(format!(
			"reading the SMTP banner: greeting does not start with `220 `: {banner_text:?}\nstderr:\n{}",
			redact_password(&stderr)
		));
	}
	if !banner_text.contains("mail.local.test") {
		let (_stdout, stderr) = child.kill_and_drain(
			Instant::now() + Duration::from_secs(2),
			"reading the SMTP banner",
		)?;
		return Err(format!(
			"reading the SMTP banner: greeting does not name mail.local.test: {banner_text:?}\nstderr:\n{}",
			redact_password(&stderr)
		));
	}

	// Negative control: real TLS handshake against the plaintext SMTP
	// listener. A probe that always returned Ok would leave this
	// section green, so the suite pins that a real probe can say NO.
	// The port is `port_base + 25`; the failure message names it so a
	// regression points at the listener instead of at the helper.
	let smtp_tls_stream = wait_for_bind(
		smtp_addr,
		bind_deadline,
		"opening a fresh connection to the SMTP port for the negative TLS probe",
		&mut child,
	)?;
	let smtp_tls_phase = format!("SMTP port {smtp_addr} must NOT be classified as TLS");
	probe_tls_real_must_fail(smtp_tls_stream, &smtp_tls_phase, &cert_pem_path)?;

	// Submission (587): plaintext SMTP greeting, same contract as 25.
	let submission_addr = SocketAddr::new(loopback, port_base + 587);
	let mut submission = wait_for_bind(
		submission_addr,
		bind_deadline,
		"waiting for submission port",
		&mut child,
	)?;
	let submission_banner = read_banner(
		&mut submission,
		Instant::now() + Duration::from_secs(2),
		"reading the submission banner",
	)?;
	drop(submission);
	let submission_text = String::from_utf8_lossy(&submission_banner);
	if !submission_text.starts_with("220 ") && !submission_text.starts_with("421 ") {
		let (_stdout, stderr) = child.kill_and_drain(
			Instant::now() + Duration::from_secs(2),
			"reading the submission banner",
		)?;
		return Err(format!(
			"reading the submission banner: greeting does not look like an SMTP response: {submission_text:?}\nstderr:\n{}",
			redact_password(&stderr)
		));
	}

	// IMAP (143): plaintext IMAP greeting, usually `* OK ... ready`.
	let imap_addr = SocketAddr::new(loopback, port_base + 143);
	let mut imap = wait_for_bind(
		imap_addr,
		bind_deadline,
		"waiting for IMAP port",
		&mut child,
	)?;
	let imap_banner = read_banner(
		&mut imap,
		Instant::now() + Duration::from_secs(2),
		"reading the IMAP banner",
	)?;
	drop(imap);
	let imap_text = String::from_utf8_lossy(&imap_banner);
	if !imap_text.starts_with("* OK") {
		let (_stdout, stderr) = child.kill_and_drain(
			Instant::now() + Duration::from_secs(2),
			"reading the IMAP banner",
		)?;
		return Err(format!(
			"reading the IMAP banner: greeting does not look like an IMAP ready line: {imap_text:?}\nstderr:\n{}",
			redact_password(&stderr)
		));
	}

	// Submissions (465): implicit TLS. The real handshake must succeed
	// and the encrypted channel must carry an SMTP `220 ` greeting; a
	// listener that accepts TCP but does not actually serve TLS would
	// fail the handshake, and a listener that finishes the handshake
	// with a different certificate would fail verification.
	let submissions_addr = SocketAddr::new(loopback, port_base + 465);
	let submissions_stream = wait_for_bind(
		submissions_addr,
		bind_deadline,
		"waiting for submissions port",
		&mut child,
	)?;
	let submissions_greeting = probe_tls_real(
		submissions_stream,
		&format!("submissions TLS probe at {submissions_addr}"),
		&cert_pem_path,
	)?;
	if !submissions_greeting.starts_with("220 ") {
		let (_stdout, stderr) = child.kill_and_drain(
			Instant::now() + Duration::from_secs(2),
			"reading the submissions greeting",
		)?;
		return Err(format!(
			"reading the submissions greeting: TLS handshake succeeded but greeting does not start with `220 `: {submissions_greeting:?}\nstderr:\n{}",
			redact_password(&stderr)
		));
	}

	// IMAPS (993): implicit TLS, same shape as submissions, greeting is
	// `* OK`.
	let imaps_addr = SocketAddr::new(loopback, port_base + 993);
	let imaps_stream = wait_for_bind(
		imaps_addr,
		bind_deadline,
		"waiting for IMAPS port",
		&mut child,
	)?;
	let imaps_greeting = probe_tls_real(
		imaps_stream,
		&format!("IMAPS TLS probe at {imaps_addr}"),
		&cert_pem_path,
	)?;
	if !imaps_greeting.starts_with("* OK") {
		let (_stdout, stderr) = child.kill_and_drain(
			Instant::now() + Duration::from_secs(2),
			"reading the IMAPS greeting",
		)?;
		return Err(format!(
			"reading the IMAPS greeting: TLS handshake succeeded but greeting does not start with `* OK`: {imaps_greeting:?}\nstderr:\n{}",
			redact_password(&stderr)
		));
	}

	// API (8025): plaintext HTTP. A `GET / HTTP/1.0` must come back
	// with an `HTTP/1.` status line so the listener is HTTP, not just
	// an open port.
	let api_addr = SocketAddr::new(loopback, port_base + 8025);
	let mut api = wait_for_bind(api_addr, bind_deadline, "waiting for API port", &mut child)?;
	use std::io::Write;
	api.set_read_timeout(Some(Duration::from_millis(500)))
		.map_err(|error| format!("waiting for API port: set_read_timeout: {error:?}"))?;
	api.write_all(b"GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
		.map_err(|error| format!("waiting for API port: write: {error:?}"))?;
	let api_response = read_banner(
		&mut api,
		Instant::now() + Duration::from_secs(2),
		"reading the API response",
	)?;
	drop(api);
	let api_text = String::from_utf8_lossy(&api_response);
	if !api_text.starts_with("HTTP/") {
		let (_stdout, stderr) = child.kill_and_drain(
			Instant::now() + Duration::from_secs(2),
			"reading the API response",
		)?;
		return Err(format!(
			"reading the API response: HTTP listener did not return an HTTP status line: {api_text:?}\nstderr:\n{}",
			redact_password(&stderr)
		));
	}

	// Kill the server, wait for the kernel to reap it, then drain
	// both pipes so any later assertion can quote the child's
	// diagnostic. `kill_and_drain` is the only path that touches the
	// pipes; calling `read_to_end` on a still-running child's pipe
	// would block forever.
	let (stdout, stderr) = child.kill_and_drain(
		Instant::now() + Duration::from_secs(2),
		"waiting for the child to exit",
	)?;
	if !stdout.is_empty() {
		return Err(format!(
			"draining child: stdout must be empty, got {} bytes: {:?}\nstderr:\n{}",
			stdout.len(),
			String::from_utf8_lossy(&stdout),
			redact_password(&stderr)
		));
	}

	// The marker file is what makes a second `epistle local` reuse
	// the directory; losing it across a clean shutdown would defeat
	// the idempotence rule the harness guarantees.
	let marker = dir.join(".epistle-local");
	if !marker.exists() {
		return Err(format!(
			"draining child: marker file vanished: {}\nstderr:\n{}",
			marker.display(),
			redact_password(&stderr)
		));
	}

	Ok(())
}

/// Spawn the real binary against a fresh tempdir, pick a free
/// loopback port base, retry only when the child's stderr carries
/// the Linux `EADDRINUSE` text, fail loudly on anything else.
/// Each attempt uses its own fresh tempdir: after attempt 1
/// persists base P in `mail.toml`, attempt 2 would probe Q but
/// the child would bind P (by design), so retrying against the
/// same directory can never recover. A fresh dir per attempt lets
/// the retry policy pick a fresh port base and lay out a clean
/// directory.
#[test]
fn local_mode_spawns_and_listens_on_six_loopback_ports() {
	let mut last_err: Option<String> = None;
	for attempt in 0..5 {
		let dir = tempfile::tempdir().expect("tempdir");
		let port_base = pick_port_base();
		match run_once(dir.path(), port_base) {
			Ok(()) => return,
			Err(message) => {
				if attempt == 4 || !is_eaddrinuse(&message) {
					panic!("{message}");
				}
				last_err = Some(message);
				// Give the OS a moment to release the socket before
				// trying a fresh port base.
				std::thread::sleep(Duration::from_millis(100));
			}
		}
	}
	if let Some(err) = last_err {
		panic!("all retries failed: {err}");
	}
}

/// Pin: the TLS probe cannot hang the suite when a peer accepts TCP
/// and never answers the handshake. The probe installs a 2 s read +
/// write timeout on the `TcpStream` before driving the handshake, so
/// a stuck peer surfaces as `Err("... handshake did not complete
/// within 2s")` rather than wedging the test thread.
///
/// The test runs the probe in its own thread and collects the result
/// over an `mpsc` channel; the main thread calls `recv_timeout` with a
/// 10 s budget. A regression that drops the read timeout makes the
/// probe hang past its internal budget, so the channel never sees a
/// message, `recv_timeout` returns `Timeout`, and the test panics
/// with a message naming the hang. A regression that wedges the probe
/// thread therefore fails the test by its own 10 s guard, NOT by
/// hanging the test harness; the suite continues.
///
/// The probe thread is NOT joined at the end: it may still be blocked
/// on a stalled read, and the OS reaps it when the test process exits.
/// The peer thread is also not joined; setting `stop` lets the peer drop
/// the socket within its 10 ms poll interval and exit on its own.
#[test]
fn tls_probe_returns_timeout_error_against_hung_peer() {
	use std::sync::Arc;
	use std::sync::atomic::{AtomicBool, Ordering};

	let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind 127.0.0.1:0");
	let port = listener.local_addr().expect("addr").port();

	// Mint a self-signed certificate the probe can use as the trust
	// anchor. The peer's TLS handshake is never completed (it never
	// sends a ServerHello), so the cert contents only matter to the
	// probe's "is the file parseable" path; the probe times out before
	// it gets far enough to validate the chain.
	let mut params =
		rcgen::CertificateParams::new(vec![TLS_SERVER_NAME.to_string()]).expect("params");
	params.distinguished_name.push(
		rcgen::DnType::CommonName,
		rcgen::DnValue::Utf8String(TLS_SERVER_NAME.to_string()),
	);
	let key_pair = rcgen::KeyPair::generate().expect("key pair");
	let cert = params.self_signed(&key_pair).expect("self sign");
	let cert_pem = cert.pem().to_string();
	let cert_dir = tempfile::tempdir().expect("tempdir");
	let cert_path = cert_dir.path().join("cert.pem");
	std::fs::write(&cert_path, cert_pem).expect("write cert");

	// Peer: accept the connection and hold the socket open until the
	// `stop` flag is set. The socket stays alive across the probe's
	// 2 s read timeout AND the test's 10 s wall-clock guard, so the
	// only path the probe has to returning is through its own
	// SO_RCVTIMEO timeout; a peer-side close would surface as
	// ConnectionReset and not exercise the timeout.
	let stop = Arc::new(AtomicBool::new(false));
	let stop_peer = Arc::clone(&stop);
	let _peer = thread::spawn(move || {
		let (stream, _) = listener.accept().expect("accept");
		while !stop_peer.load(Ordering::Relaxed) {
			thread::sleep(Duration::from_millis(10));
		}
		drop(stream);
	});

	// Probe: run on its own thread and send the result back over a
	// channel. The main thread waits at most 10 s; beyond that the
	// probe has hung and the test fails by its own budget.
	let (tx, rx) = mpsc::channel::<Result<String, String>>();
	let probe_phase = format!("hung peer at 127.0.0.1:{port}");
	let probe_cert_path = cert_path.clone();
	let _probe = thread::spawn(move || {
		let stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).expect("connect");
		let result = probe_tls_real(stream, &probe_phase, &probe_cert_path);
		let _ = tx.send(result);
	});

	let result = match rx.recv_timeout(Duration::from_secs(10)) {
		Ok(result) => result,
		Err(mpsc::RecvTimeoutError::Timeout) => {
			panic!("probe hung past its 10 s wall-clock budget (the read timeout was dropped)")
		}
		Err(mpsc::RecvTimeoutError::Disconnected) => {
			panic!("probe thread disconnected before sending a result")
		}
	};

	let err = match result {
		Ok(greeting) => {
			panic!("probe against a hung peer must return Err, got Ok greeting {greeting:?}")
		}
		Err(error) => error,
	};
	assert!(
		err.contains("handshake"),
		"error must name the handshake phase, got: {err}"
	);
	assert!(
		err.contains(&port.to_string()),
		"error must name the listener port {port}, got: {err}"
	);

	// Release the peer so it drops the socket. The probe thread may
	// still be blocked on the stalled handshake; we do not join it.
	stop.store(true, Ordering::Relaxed);
}
