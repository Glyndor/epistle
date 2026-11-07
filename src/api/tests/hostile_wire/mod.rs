//! Real HTTP peers with an out-of-process wall-clock and Linux RSS watchdog.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const CHILD: &str = "EPISTLE_HOSTILE_HTTP_CHILD";
const DEADLINE: Duration = Duration::from_secs(30);
const MAX_RSS_KIB: u64 = 128 * 1024;

/// Return true in the supervisor, false in the isolated test worker.
/// A process deadline also catches synchronous handlers that never yield.
/// The RSS ceiling includes runtime, fixtures and request/response buffers.
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
			let peak = status.lines().find_map(|line| {
				line.strip_prefix("VmHWM:")?
					.split_whitespace()
					.next()?
					.parse::<u64>()
					.ok()
			});
			if peak.is_some_and(|kib| kib > MAX_RSS_KIB) {
				violation = Some("HTTP worker exceeded 128 MiB peak RSS");
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
			.timeout(Duration::from_secs(5))
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
