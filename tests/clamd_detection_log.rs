//! Integration test for the WARN event emitted by `ClamdHook::scan` on a
//! clamd FOUND reply.
//!
//! The same check lived in `src/antispam/clamd_tests.rs` as a unit test. The
//! `tracing` per-thread dispatcher is shared with every other test in the
//! lib binary, and parallel runs installed and dropped their own layers while
//! this test was polling: roughly one run in six captured zero WARNs against
//! the one the hook fires, and the original wrapper around the polling
//! future did not move the failure surface. Running it as an integration
//! test in its own binary gives the subscriber this test installs the whole
//! process, so no other test can race with it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use epistle::antispam::clamd::ClamdHook;
use epistle::antispam::hook::{HookVerdict, MailHook};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tracing::field::{Field, Visit};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::SubscriberExt;

#[derive(Default)]
struct Capture {
	events: Arc<Mutex<Vec<HashMap<String, String>>>>,
}

impl<S: tracing::Subscriber> Layer<S> for Capture {
	fn on_event(
		&self,
		event: &tracing::Event<'_>,
		_ctx: tracing_subscriber::layer::Context<'_, S>,
	) {
		if *event.metadata().level() != tracing::Level::WARN {
			return;
		}
		let mut fields = HashMap::new();
		event.record(&mut FieldVisitor {
			fields: &mut fields,
		});
		self.events.lock().expect("capture").push(fields);
	}
}

struct FieldVisitor<'a> {
	fields: &'a mut HashMap<String, String>,
}

impl Visit for FieldVisitor<'_> {
	fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
		self.fields
			.insert(field.name().to_string(), format!("{value:?}"));
	}
	fn record_str(&mut self, field: &Field, value: &str) {
		self.fields
			.insert(field.name().to_string(), value.to_string());
	}
	fn record_i64(&mut self, field: &Field, value: i64) {
		self.fields
			.insert(field.name().to_string(), value.to_string());
	}
	fn record_u64(&mut self, field: &Field, value: u64) {
		self.fields
			.insert(field.name().to_string(), value.to_string());
	}
	fn record_bool(&mut self, field: &Field, value: bool) {
		self.fields
			.insert(field.name().to_string(), value.to_string());
	}
}

#[test]
fn detection_log_contains_signature_and_size_without_message() {
	let capture = Capture::default();
	let events = capture.events.clone();
	// The integration-test binary runs this single test, so the global
	// subscriber this installs is the only one in scope for its duration.
	let subscriber = tracing_subscriber::registry().with(capture);
	tracing::subscriber::set_global_default(subscriber).expect("global subscriber");

	let runtime = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()
		.expect("current-thread runtime");
	runtime.block_on(async {
		let dir = tempfile::tempdir().expect("tempdir");
		let socket = dir.path().join("clamd.sock");
		let listener = UnixListener::bind(&socket).expect("bind fake clamd");

		let server = tokio::spawn(async move {
			let (mut stream, _) = listener.accept().await.expect("accept");
			let mut header = [0u8; 10];
			stream.read_exact(&mut header).await.expect("header");
			assert_eq!(&header, b"zINSTREAM\0");
			loop {
				let mut length = [0u8; 4];
				stream.read_exact(&mut length).await.expect("length");
				let chunk_length = u32::from_be_bytes(length) as usize;
				if chunk_length == 0 {
					break;
				}
				let mut chunk = vec![0u8; chunk_length];
				stream.read_exact(&mut chunk).await.expect("chunk");
			}
			stream
				.write_all(b"stream: Eicar-Test-Signature FOUND\0")
				.await
				.expect("reply");
		});

		let raw = uuid::Uuid::now_v7().simple().to_string();
		let hook = ClamdHook::new(socket);
		let verdict = hook.scan(raw.as_bytes()).await;
		assert_eq!(verdict, HookVerdict::Quarantine);

		let captured = std::mem::take(&mut *events.lock().expect("capture"));
		assert_eq!(captured.len(), 1, "exactly one WARN event");
		let fields = &captured[0];
		assert_eq!(
			fields.get("signature").map(String::as_str),
			Some("Eicar-Test-Signature")
		);
		assert_eq!(
			fields.get("message_bytes").map(String::as_str),
			Some(raw.len().to_string().as_str())
		);
		for value in fields.values() {
			assert!(
				!value.contains(&raw),
				"message text leaked into a log field: {value}"
			);
		}

		server.await.expect("server task");
	});
}
