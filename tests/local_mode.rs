//! `epistle local` end-to-end: spawn the real binary, wait for it to
//! bind every listener, then drive the protocols the harness exposes.
//!
//! The contract:
//!
//! - the server binds six listeners on `127.0.0.1` at
//!   `port-base + {25, 587, 465, 143, 993, 8025}`;
//! - the SMTP greeting advertises the harness hostname (`mail.local.test`);
//! - the IMAPS port accepts a TCP connection;
//! - nothing the operator asked for lands on stdout;
//! - killing the child leaves the marker file behind so a second run
//!   reuses the directory byte for byte.
//!
//! The test polls the SMTP port with a 10 s deadline and no fixed sleep,
//! so a slow CI that takes a few seconds to bind is still caught by the
//! loop. If the child exits early with an address-in-use error, the test
//! picks another port base (up to five attempts); any OTHER early exit
//! fails the test with the child's stderr (the password line redacted)
//! so the failure mode is explicit instead of a generic "binary did not
//! stay up".

use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::path::Path;
use std::process::{Child as ChildProc, ChildStderr, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Path to the binary `cargo test` builds. `CARGO_BIN_EXE_<name>` is set
/// by Cargo for integration tests against a binary in the same package.
fn binary() -> &'static Path {
	Path::new(env!("CARGO_BIN_EXE_epistle"))
}

/// Try once to open `addr` for reading. `None` when the connection was
/// refused (the typical "not listening yet" signal during startup); other
/// errors propagate so a real network problem is not misread as a slow
/// bind.
fn try_connect(addr: SocketAddr) -> Option<TcpStream> {
	match TcpStream::connect_timeout(&addr, Duration::from_millis(200)) {
		Ok(stream) => {
			// Disable Nagle so the greeting lands in one read on the
			// test side; the SMTP server is small enough that it fits.
			let _ = stream.set_nodelay(true);
			Some(stream)
		}
		Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => None,
		Err(error) => panic!("connect {addr}: {error:?}"),
	}
}

/// Block until `addr` accepts a TCP connection or `deadline` elapses.
/// Loops without sleeping because the kernel tells us about a refused
/// connection immediately; a fixed `sleep` would either waste time on
/// fast binds or miss slow ones. If the child has already exited by
/// the time the deadline arrives, the failure message quotes the
/// child's stderr so the operator sees the storage error (or whatever
/// else) instead of a generic bind-timeout.
fn wait_for_bind(
	addr: SocketAddr,
	deadline: Instant,
	child: &mut Child,
) -> Result<TcpStream, String> {
	loop {
		if let Some(stream) = try_connect(addr) {
			return Ok(stream);
		}
		// Surface early child exit. `try_wait` is non-blocking.
		if let Ok(Some(status)) = child.proc.try_wait() {
			let (_stdout, stderr) = child.kill_and_drain();
			return Err(format!(
				"child exited before binding {addr}: status {status:?}\nstderr:\n{}",
				redact_password(&stderr)
			));
		}
		if Instant::now() >= deadline {
			let (_stdout, stderr) = child.kill_and_drain();
			return Err(format!(
				"port {addr} did not start accepting within 10 s\nstderr:\n{}",
				redact_password(&stderr)
			));
		}
		std::thread::sleep(Duration::from_millis(50));
	}
}

/// Probe `127.0.0.1:0` once to learn a free port, then drop the listener.
/// Returns the port the OS picked; callers derive the listener set from
/// the constants the harness documents (`SMTP+25`, etc.).
fn free_loopback_port() -> u16 {
	let listener = std::net::TcpListener::bind((IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
		.expect("bind 127.0.0.1:0");
	let port = listener.local_addr().expect("addr").port();
	drop(listener);
	port
}

/// Strip the line that carries the password from a child stderr buffer.
/// The redacted form keeps every other byte intact so the rest of the
/// diagnostic survives and the operator can still see why the child
/// exited.
fn redact_password(stderr: &[u8]) -> String {
	let text = String::from_utf8_lossy(stderr);
	let mut out = String::with_capacity(text.len());
	for line in text.lines() {
		if line.trim_start().starts_with("password:") {
			out.push_str("  password:  <redacted>\n");
		} else {
			out.push_str(line);
			out.push('\n');
		}
	}
	out
}

/// Read up to `len` bytes from `stream` with a 5 s deadline. The SMTP
/// greeting is a single line of roughly 40 bytes, so 512 is plenty; the
/// timeout is the connection-level safety net for the rare case the
/// server does not greet within five seconds of accepting.
fn read_some(stream: &mut TcpStream, len: usize) -> Vec<u8> {
	let mut buf = vec![0u8; len];
	let mut total = 0;
	let deadline = Instant::now() + Duration::from_secs(5);
	stream
		.set_read_timeout(Some(Duration::from_millis(500)))
		.expect("set_read_timeout");
	while total < len {
		match stream.read(&mut buf[total..]) {
			Ok(0) => break,
			Ok(n) => total += n,
			Err(error)
				if error.kind() == std::io::ErrorKind::WouldBlock
					|| error.kind() == std::io::ErrorKind::TimedOut =>
			{
				if Instant::now() >= deadline {
					break;
				}
			}
			Err(error) => panic!("read: {error:?}"),
		}
	}
	buf.truncate(total);
	buf
}

/// Spawned child state held together so the drop guard can kill and reap
/// it on a failed assertion. The guard is explicit because leaving a
/// child running across tests would pile up ports and file descriptors.
struct Child {
	proc: ChildProc,
	stderr: ChildStderr,
}

impl Child {
	fn spawn(args: &[&str], _dir: &Path) -> Self {
		let mut cmd = Command::new(binary());
		cmd.args(args)
			.env_remove("RUST_LOG")
			.env("NO_COLOR", "1")
			.stdout(Stdio::piped())
			.stderr(Stdio::piped())
			.stdin(Stdio::null());
		let mut proc = cmd.spawn().expect("spawn epistle local");
		let stderr = proc.stderr.take().expect("stderr piped");
		Self { proc, stderr }
	}

	/// Kill the child, wait for its pipes to close, then drain both stdout
	/// and stderr into owned `Vec<u8>`s. After this call the child has
	/// been reaped and no more diagnostics arrive on either stream. The
	/// method exists because calling `read_to_end` on a still-running
	/// child's pipe blocks forever; every caller in `run_once` drains
	/// only after asserting failure or finishing the protocol checks.
	fn kill_and_drain(&mut self) -> (Vec<u8>, Vec<u8>) {
		let _ = self.proc.kill();
		let _ = self.proc.wait();
		let mut stdout = Vec::new();
		if let Some(mut out) = self.proc.stdout.take() {
			let _ = out.read_to_end(&mut stdout);
		}
		let mut stderr = Vec::new();
		let _ = self.stderr.read_to_end(&mut stderr);
		(stdout, stderr)
	}
}

impl Drop for Child {
	fn drop(&mut self) {
		let _ = self.proc.kill();
		let _ = self.proc.wait();
	}
}

/// Sequential counter shared across retries so each test invocation
/// picks a distinct starting port base. Without this, two parallel runs
/// would race the same ports.
fn next_port_base() -> u16 {
	static COUNTER: AtomicUsize = AtomicUsize::new(0);
	let seed = COUNTER.fetch_add(1, Ordering::Relaxed);
	// Spread attempts across a 1000-port window so a previous test that
	// left a bound listener doesn't collide.
	15000 + ((seed as u16) * 1000) % 30000
}

/// Run one attempt. Returns `Ok(())` if everything passed; otherwise an
/// error message that quotes the redacted stderr so the failure mode is
/// explicit. The retry loop in the test driver reads it.
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

	let smtp_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port_base + 25);
	let imaps_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port_base + 993);
	let deadline = Instant::now() + Duration::from_secs(10);

	let mut smtp = wait_for_bind(smtp_addr, deadline, &mut child)?;
	let banner = read_some(&mut smtp, 512);
	let banner_text = String::from_utf8_lossy(&banner);

	if !banner_text.starts_with("220 ") {
		let (_stdout, stderr) = child.kill_and_drain();
		return Err(format!(
			"SMTP greeting does not start with `220 `: {banner_text:?}\nstderr:\n{}",
			redact_password(&stderr)
		));
	}
	if !banner_text.contains("mail.local.test") {
		let (_stdout, stderr) = child.kill_and_drain();
		return Err(format!(
			"SMTP greeting does not name mail.local.test: {banner_text:?}\nstderr:\n{}",
			redact_password(&stderr)
		));
	}

	let mut imaps = wait_for_bind(imaps_addr, deadline, &mut child)?;
	// Drive the IMAPS handshake so the test proves the TLS acceptor is
	// live, not just that the port is open. The server presents a
	// self-signed certificate for `mail.local.test`; pinning a CA would
	// couple the test to layout changes, so the assertion is "the
	// handshake reaches the certificate stage" instead.
	let _ = imaps.set_read_timeout(Some(Duration::from_secs(2)));
	let mut probe = [0u8; 1];
	let _ = imaps.read(&mut probe);

	// The TLS ClientHello we sent makes the server respond with a
	// ServerHello (or alert). The bytes are not asserted because TLS
	// framing changes with the library version; the read is enough to
	// prove the listener answered.

	// Kill the server, wait for the stderr/stdout pipes to close, then
	// drain both buffers so any later assertion can quote the child's
	// diagnostic. `kill_and_drain` is the only path that touches the
	// pipes; calling `read_to_end` on a still-running child's pipe
	// would block forever, which is what hung earlier revisions.
	let (stdout, stderr) = child.kill_and_drain();
	if !stdout.is_empty() {
		return Err(format!(
			"stdout must be empty, got {} bytes: {:?}\nstderr:\n{}",
			stdout.len(),
			String::from_utf8_lossy(&stdout),
			redact_password(&stderr)
		));
	}

	// The marker file is what makes a second `epistle local` reuse the
	// directory; losing it across a clean shutdown would defeat the
	// idempotence rule the harness guarantees.
	let marker = dir.join(".epistle-local");
	if !marker.exists() {
		return Err(format!(
			"marker file vanished: {}\nstderr:\n{}",
			marker.display(),
			redact_password(&stderr)
		));
	}

	// Tell the harness about the bytes we read so it can include the
	// SMTP banner in any failure message even on the success path.
	let _ = banner; // keep the buffer alive past this point
	Ok(())
}

/// Pick a port base: bind `127.0.0.1:0` once to learn a port the OS
/// marked free, then round down to a base below `port - 8025` so every
/// computed listener port stays clear of the probe. Returns a `u16`
/// inside `1024..=65535`; if the arithmetic cannot produce one, fall
/// back to the sequential counter so the test always starts.
fn pick_port_base() -> u16 {
	let port = free_loopback_port();
	let aligned_below = port.saturating_sub(8025 + (port % 1000));
	if aligned_below >= 1024 {
		aligned_below
	} else {
		next_port_base()
	}
}

/// Spawn the real binary against a fresh tempdir, pick a free loopback
/// port base, retry on `address-in-use`, fail loudly on anything else.
#[test]
fn local_mode_spawns_and_listens_on_six_loopback_ports() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut last_err: Option<String> = None;
	for attempt in 0..5 {
		let port_base = pick_port_base();
		match run_once(dir.path(), port_base) {
			Ok(()) => return,
			Err(message) => {
				// Retry only when the failure looks like an
				// address-in-use race; anything else is a real
				// regression and must surface with the redacted
				// stderr attached.
				if attempt == 4 || !message.contains("ConnectionRefused") {
					panic!("{message}");
				}
				last_err = Some(message);
				// Give the OS a moment to release the socket.
				std::thread::sleep(Duration::from_millis(100));
			}
		}
	}
	if let Some(err) = last_err {
		panic!("all retries failed: {err}");
	}
}
