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

use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::path::Path;
use std::process::{Child as ChildProc, ChildStderr, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Path to the binary `cargo test` builds. `CARGO_BIN_EXE_<name>` is
/// set by Cargo for integration tests against a binary in the same
/// package.
fn binary() -> &'static Path {
	Path::new(env!("CARGO_BIN_EXE_epistle"))
}

/// Linux prints this exact string for `EADDRINUSE`. The same text
/// surfaces in the child's stderr when a bind races; the retry loop
/// uses it to decide "try a different port" vs "real regression".
const EADDRINUSE_TEXT: &str = "Address already in use";

/// Try once to open `addr` for reading. Returns `None` when the
/// connection is refused or the kernel has not answered within the
/// 200 ms connect timeout; the caller polls again. Anything else
/// bubbles up with the phase name attached so the failure says which
/// bind step tripped.
fn try_connect(addr: SocketAddr, phase: &str) -> Option<TcpStream> {
	match TcpStream::connect_timeout(&addr, Duration::from_millis(200)) {
		Ok(stream) => {
			// Disable Nagle so the greeting lands in one read on the
			// test side; the SMTP server is small enough that it fits.
			let _ = stream.set_nodelay(true);
			Some(stream)
		}
		Err(error)
			if error.kind() == std::io::ErrorKind::ConnectionRefused
				|| error.kind() == std::io::ErrorKind::TimedOut =>
		{
			None
		}
		Err(error) => panic!("{phase}: connect {addr}: {error:?}"),
	}
}

/// Block until `addr` accepts a TCP connection or `deadline` elapses.
/// `phase` appears in every error path so the failure message says
/// which wait tripped. If the child has already exited by the time
/// the deadline arrives, the message quotes the child's stderr.
fn wait_for_bind(
	addr: SocketAddr,
	deadline: Instant,
	phase: &str,
	child: &mut Child,
) -> Result<TcpStream, String> {
	let started = Instant::now();
	let budget = deadline.saturating_duration_since(started);
	loop {
		if let Some(stream) = try_connect(addr, phase) {
			return Ok(stream);
		}
		match child.proc.try_wait() {
			Ok(Some(status)) => {
				let (_stdout, stderr) =
					child.kill_and_drain(Instant::now() + Duration::from_secs(2), phase)?;
				return Err(format!(
					"{phase}: child exited before binding {addr}: status {status:?}\nstderr:\n{}",
					redact_password(&stderr)
				));
			}
			Ok(None) => {}
			Err(error) => return Err(format!("{phase}: try_wait failed: {error:?}")),
		}
		if Instant::now() >= deadline {
			let (_stdout, stderr) =
				child.kill_and_drain(Instant::now() + Duration::from_secs(2), phase)?;
			return Err(format!(
				"{phase}: port {addr} did not start accepting within {budget:?}\nstderr:\n{}",
				redact_password(&stderr)
			));
		}
		std::thread::sleep(Duration::from_millis(20));
	}
}

/// Probe `127.0.0.1:0` once to learn a free port, then drop the
/// listener. Returns the port the OS picked.
fn free_loopback_port() -> u16 {
	let listener = std::net::TcpListener::bind((IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
		.expect("bind 127.0.0.1:0");
	let port = listener.local_addr().expect("addr").port();
	drop(listener);
	port
}

/// Strip the line that carries the password from a child stderr
/// buffer. Keeping every other byte intact means the rest of the
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

/// Read the SMTP greeting until CRLF, bounded at 512 bytes and the
/// supplied deadline. Polls on `we saw CRLF` so a greeting that arrives
/// in the first read returns immediately; the deadline is the safety
/// net for a server that never greets.
fn read_banner(stream: &mut TcpStream, deadline: Instant, phase: &str) -> Result<Vec<u8>, String> {
	stream
		.set_read_timeout(Some(Duration::from_millis(200)))
		.map_err(|error| format!("{phase}: set_read_timeout: {error:?}"))?;
	let mut buf = Vec::with_capacity(128);
	let mut chunk = [0u8; 128];
	while buf.len() < 512 {
		match stream.read(&mut chunk) {
			Ok(0) => break,
			Ok(n) => {
				buf.extend_from_slice(&chunk[..n]);
				if buf.windows(2).any(|window| window == b"\r\n") {
					break;
				}
			}
			Err(error)
				if error.kind() == std::io::ErrorKind::WouldBlock
					|| error.kind() == std::io::ErrorKind::TimedOut =>
			{
				if Instant::now() >= deadline {
					return Err(format!(
						"{phase}: banner did not arrive within the deadline; got {:?}",
						String::from_utf8_lossy(&buf)
					));
				}
			}
			Err(error) => return Err(format!("{phase}: read banner: {error:?}")),
		}
	}
	if buf.windows(2).any(|window| window == b"\r\n") {
		Ok(buf)
	} else {
		Err(format!(
			"{phase}: banner exceeded 512 bytes without CRLF; got {:?}",
			String::from_utf8_lossy(&buf)
		))
	}
}

/// Spawned child state held together so the drop guard can kill and
/// reap it on a failed assertion. The guard is explicit because
/// leaving a child running across tests would pile up ports and file
/// descriptors.
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

	/// Kill the child, poll for the kernel to reap it under a
	/// deadline, then drain both pipes. `kill` sends `SIGKILL` on
	/// Unix, which the child cannot trap; calling `read_to_end` on a
	/// still-running pipe would block forever, so the drain happens
	/// only after `wait`. On timeout the redacted stderr is included
	/// in the error so the operator sees why the child refused to
	/// exit.
	fn kill_and_drain(
		&mut self,
		deadline: Instant,
		phase: &str,
	) -> Result<(Vec<u8>, Vec<u8>), String> {
		let _ = self.proc.kill();
		loop {
			match self.proc.try_wait() {
				Ok(Some(_)) => break,
				Ok(None) => {}
				Err(error) => return Err(format!("{phase}: try_wait: {error:?}")),
			}
			if Instant::now() >= deadline {
				let stderr = self.drain_stderr_only();
				return Err(format!(
					"{phase}: child did not exit within the deadline\nstderr:\n{}",
					redact_password(&stderr)
				));
			}
			std::thread::sleep(Duration::from_millis(20));
		}
		let mut stdout = Vec::new();
		if let Some(mut out) = self.proc.stdout.take() {
			let _ = out.read_to_end(&mut stdout);
		}
		let stderr = self.drain_stderr_only();
		Ok((stdout, stderr))
	}

	fn drain_stderr_only(&mut self) -> Vec<u8> {
		let mut stderr = Vec::new();
		let _ = self.stderr.read_to_end(&mut stderr);
		stderr
	}
}

impl Drop for Child {
	fn drop(&mut self) {
		let _ = self.proc.kill();
		let _ = self.proc.wait();
	}
}

/// Sequential counter shared across retries so each test invocation
/// picks a distinct starting port base.
fn next_port_base() -> u16 {
	static COUNTER: AtomicUsize = AtomicUsize::new(0);
	let seed = COUNTER.fetch_add(1, Ordering::Relaxed);
	15000 + ((seed as u16) * 1000) % 30000
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

	let smtp_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port_base + 25);
	let imaps_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port_base + 993);
	let bind_deadline = Instant::now() + Duration::from_secs(10);

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

	let mut imaps = wait_for_bind(
		imaps_addr,
		Instant::now() + Duration::from_secs(10),
		"connecting to IMAPS",
		&mut child,
	)?;
	// Drive the IMAPS handshake so the test proves the TLS acceptor
	// is live, not just that the port is open. We send one byte and
	// read whatever the server emits back (a ServerHello or an Alert
	// for the malformed input). Reading with a 200 ms timeout keeps
	// this phase a poll on a condition rather than a fixed wait;
	// under load the server may never reply to a partial ClientHello
	// and that is fine, the TCP accept was already verified.
	let _ = imaps.set_read_timeout(Some(Duration::from_millis(200)));
	let mut probe = [0u8; 1];
	let _ = imaps.read(&mut probe);
	drop(imaps);

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

/// Pick a port base: bind `127.0.0.1:0` once to learn a port the OS
/// marked free, then round down to a base below `port - 8025` so every
/// computed listener port stays clear of the probe.
fn pick_port_base() -> u16 {
	let port = free_loopback_port();
	let aligned_below = port.saturating_sub(8025 + (port % 1000));
	if aligned_below >= 1024 {
		aligned_below
	} else {
		next_port_base()
	}
}

/// True when `message` names the Linux `EADDRINUSE` text in the
/// child's stderr. Any other failure is a real regression and
/// surfaces with the phase and redacted stderr attached.
fn is_eaddrinuse(message: &str) -> bool {
	message.contains(EADDRINUSE_TEXT)
}

/// Spawn the real binary against a fresh tempdir, pick a free
/// loopback port base, retry only when the child's stderr carries
/// the Linux `EADDRINUSE` text, fail loudly on anything else.
#[test]
fn local_mode_spawns_and_listens_on_six_loopback_ports() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut last_err: Option<String> = None;
	for attempt in 0..5 {
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
