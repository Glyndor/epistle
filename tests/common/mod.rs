//! Shared helpers for the `epistle local` integration tests. Every
//! helper here was originally in `tests/local_mode.rs`; the restart
//! test split them out so neither file would cross the 500-code-line
//! cap. Each `tests/*.rs` is a separate Cargo
//! binary, so the helpers are pulled in via `mod common;` with a
//! `#[path]` attribute.

use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::path::Path;
use std::process::{Child as ChildProc, ChildStderr, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Path to the binary `cargo test` builds. `CARGO_BIN_EXE_<name>` is
/// set by Cargo for integration tests against a binary in the same
/// package.
pub fn binary() -> &'static Path {
	Path::new(env!("CARGO_BIN_EXE_epistle"))
}

/// Linux prints this exact string for `EADDRINUSE`. The same text
/// surfaces in the child's stderr when a bind races; the retry loop
/// uses it to decide "try a different port" vs "real regression".
pub const EADDRINUSE_TEXT: &str = "Address already in use";

/// Maximum time the harness waits for the `epistle local` child to
/// bind every listener before failing the attempt. The bind check
/// itself is a poll on `connect` succeeding, so a passing run
/// returns as soon as the last port accepts a connection; the
/// deadline is the safety net for a slow start. Sized to fit the
/// cost of running the test binary under `cargo llvm-cov` on a
/// shared runner, where the instrumented child can take noticeably
/// longer to reach its `listen` calls.
pub const BIND_DEADLINE: Duration = Duration::from_secs(30);

/// Maximum time the harness waits for a single banner or greeting
/// read (SMTP, submission, IMAP, or the HTTP status line) to
/// complete. The reader polls on `we saw CRLF`, so a passing run
/// returns as soon as the terminator lands in the buffer; the
/// deadline is the safety net for a listener that accepts TCP and
/// never greets. Sized to fit the same slow-start budget as
/// [`BIND_DEADLINE`].
pub const BANNER_READ_DEADLINE: Duration = Duration::from_secs(15);

/// Read and write timeouts the TLS probe installs on the TCP
/// socket before driving the handshake. Without them a peer that
/// accepts the TCP connection and never answers blocks `read` /
/// `write` forever and the test harness cannot reap the child
/// process; setting SO_RCVTIMEO / SO_SNDTIMEO turns a stuck peer
/// into a `TimedOut` error the probe can name with the phase. The
/// hung-peer test pins the silent case with a watchdog of three
/// times this constant.
#[allow(dead_code)] // only the `local_mode` target drives a TLS handshake; the restart target shares the constant.
pub const TLS_PROBE_IO_TIMEOUT: Duration = Duration::from_secs(10);

/// Try once to open `addr` for reading. Returns `None` when the
/// connection is refused or the kernel has not answered within the
/// 200 ms connect timeout; the caller polls again. Anything else
/// bubbles up with the phase name attached so the failure says which
/// bind step tripped.
pub fn try_connect(addr: SocketAddr, phase: &str) -> Option<TcpStream> {
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
pub fn wait_for_bind(
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
					child.kill_and_drain(Instant::now() + BANNER_READ_DEADLINE, phase)?;
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
				child.kill_and_drain(Instant::now() + BANNER_READ_DEADLINE, phase)?;
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
pub fn free_loopback_port() -> u16 {
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
pub fn redact_password(stderr: &[u8]) -> String {
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
pub fn read_banner(
	stream: &mut TcpStream,
	deadline: Instant,
	phase: &str,
) -> Result<Vec<u8>, String> {
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
pub struct Child {
	pub proc: ChildProc,
	pub stderr: ChildStderr,
}

impl Child {
	pub fn spawn(args: &[&str], _dir: &Path) -> Self {
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
	/// deadline, then drain both pipes.
	pub fn kill_and_drain(
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

	pub fn drain_stderr_only(&mut self) -> Vec<u8> {
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
pub fn next_port_base() -> u16 {
	static COUNTER: AtomicUsize = AtomicUsize::new(0);
	let seed = COUNTER.fetch_add(1, Ordering::Relaxed);
	15000 + ((seed as u16) * 1000) % 30000
}

/// Pick a port base: bind `127.0.0.1:0` once to learn a port the OS
/// marked free, then round down to a base below `port - 8025` so every
/// computed listener port stays clear of the probe.
pub fn pick_port_base() -> u16 {
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
pub fn is_eaddrinuse(message: &str) -> bool {
	message.contains(EADDRINUSE_TEXT)
}
