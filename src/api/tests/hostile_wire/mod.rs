//! Real HTTP peers with an out-of-process wall-clock and Linux memory watchdog.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[cfg(all(test, target_os = "linux"))]
mod watchdog;

const CHILD: &str = "EPISTLE_HOSTILE_HTTP_CHILD";
const DEADLINE: Duration = Duration::from_secs(30);
/// The ceiling is for a worker that buffers without bound, so it watches the
/// anonymous memory (`RssAnon`: heap, stacks, mmap) and not the whole RSS.
/// `VmHWM` also counts the file pages of the test binary that the kernel has
/// mapped, and that binary is ~1 GB with debug info: on a laptop the isolated
/// worker showed `VmHWM` of 66 to 90 MiB, of which 53 to 69 MiB were
/// `RssFile` and only 7 to 27 MiB `RssAnon` (14 workers, 10 ms polling,
/// `MALLOC_ARENA_MAX` made no difference). How many file pages are resident
/// depends on read-ahead and fault-around of the host, not on the code, which
/// is why a CI runner crossed the old 256 MiB `VmHWM` line in an unrelated
/// test. The anonymous peak is 27 MiB at most, so 128 MiB leaves a factor of
/// four and still stops a worker that keeps growing (see `watchdog`).
const MAX_ANON_KIB: u64 = 128 * 1024;

/// A build instrumented for coverage keeps counters for every line and its
/// worker peaks several times higher than a plain one while the code is
/// the same, so the ceiling is four times higher there. `cargo llvm-cov`
/// sets both variables for the test processes it starts.
fn max_anon_kib() -> u64 {
	let instrumented = std::env::var_os("LLVM_PROFILE_FILE").is_some()
		|| std::env::var_os("CARGO_LLVM_COV").is_some();
	if instrumented {
		MAX_ANON_KIB * 4
	} else {
		MAX_ANON_KIB
	}
}

/// Return true in the supervisor, false in the isolated test worker.
/// A process deadline also catches synchronous handlers that never yield.
/// The memory ceiling includes runtime, fixtures and request/response buffers.
pub(in crate::api) fn supervised(module: &str, test: &str) -> bool {
	let name = format!("{}::{test}", module.split_once("::").unwrap().1);
	if std::env::var(CHILD).as_deref() == Ok(name.as_str()) {
		return false;
	}
	let mut child = Command::new(std::env::current_exe().expect("test binary"))
		.args(["--exact", &name, "--nocapture", "--test-threads=1"])
		.env(CHILD, &name)
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.spawn()
		.expect("isolated HTTP test");
	let started = Instant::now();
	let mut violation = None;
	loop {
		if child.try_wait().expect("worker status").is_some() {
			break;
		}
		if started.elapsed() > DEADLINE {
			violation = Some("HTTP worker exceeded 30 seconds");
		}
		#[cfg(target_os = "linux")]
		if let Ok(status) = std::fs::read_to_string(format!("/proc/{}/status", child.id())) {
			let anon = status.lines().find_map(|line| {
				line.strip_prefix("RssAnon:")?
					.split_whitespace()
					.next()?
					.parse::<u64>()
					.ok()
			});
			if anon.is_some_and(|kib| kib > max_anon_kib()) {
				violation = Some("HTTP worker exceeded its anonymous memory ceiling");
			}
		}
		if violation.is_some() {
			child.kill().expect("stop resource violation");
			break;
		}
		std::thread::sleep(Duration::from_millis(10));
	}
	let output = child.wait_with_output().expect("worker output");
	assert!(
		violation.is_none() && output.status.success(),
		"{name}: {violation:?}\n{}\n{}",
		String::from_utf8_lossy(&output.stdout),
		String::from_utf8_lossy(&output.stderr)
	);
	// An exact-name typo must never produce a successful run of zero tests.
	assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
	true
}

pub(in crate::api) struct Peer {
	pub base: String,
	pub client: reqwest::Client,
	task: tokio::task::JoinHandle<()>,
}

impl Peer {
	pub async fn start(app: axum::Router) -> Self {
		Self::start_within(app, Duration::from_secs(5)).await
	}

	/// [`Self::start`] with a longer wait for each answer, for a request whose
	/// honest cost is a password hash: Argon2 and a 600000 round SCRAM
	/// derivation in a debug build take seconds on a loaded machine.
	pub async fn start_within(app: axum::Router, wait: Duration) -> Self {
		let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
			.await
			.expect("real HTTP bind (requires sockets)");
		let base = format!("http://{}", listener.local_addr().unwrap());
		let task = tokio::spawn(async move {
			axum::serve(
				listener,
				app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
			)
			.await
			.expect("HTTP server");
		});
		let client = reqwest::Client::builder()
			.no_proxy()
			.redirect(reqwest::redirect::Policy::none())
			.timeout(wait)
			.build()
			.unwrap();
		Self { base, client, task }
	}

	pub async fn json(
		&self,
		path: &str,
		body: serde_json::Value,
	) -> (axum::http::StatusCode, serde_json::Value) {
		read(
			self.client
				.post(format!("{}{path}", self.base))
				.header("Content-Type", "application/json")
				.body(body.to_string())
				.send()
				.await
				.expect("HTTP response"),
		)
		.await
	}

	pub async fn healthy(&self) {
		let (status, body) = read(
			self.client
				.get(format!("{}/healthz", self.base))
				.send()
				.await
				.expect("server remains reachable"),
		)
		.await;
		assert_eq!(status, axum::http::StatusCode::OK);
		assert_eq!(body["status"], "ok");
	}
}

impl Drop for Peer {
	fn drop(&mut self) {
		self.task.abort();
	}
}

/// Bound the response even when production accidentally reflects a huge input.
pub(in crate::api) async fn read(
	mut response: reqwest::Response,
) -> (axum::http::StatusCode, serde_json::Value) {
	let status = response.status();
	let mut body = Vec::new();
	while let Some(chunk) = response.chunk().await.expect("response bytes") {
		assert!(
			body.len() + chunk.len() <= 16 * 1024,
			"response exceeds 16 KiB"
		);
		body.extend_from_slice(&chunk);
	}
	let json = serde_json::from_slice(&body).expect("JSON response");
	(status, json)
}
