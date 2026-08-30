//! Test-only tracing event capture.
//!
//! `validate_tests.rs` and `serve_tasks_tests.rs` both need to assert that a
//! piece of code emits (or does not emit) a specific warning. The same
//! `tracing` machinery is the right tool for both: install a custom `Layer`
//! on the thread-local subscriber, run the code, and read what was recorded.
//! Keeping the recorder here lets the two callers share one implementation
//! instead of each inventing its own.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tracing::Level;
use tracing::field::{Field, Visit};
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::{Layer, Registry};

#[derive(Clone, Debug)]
pub(crate) struct CapturedEvent {
	pub(crate) level: Level,
	pub(crate) fields: HashMap<String, String>,
}

#[derive(Default)]
pub(crate) struct Capture {
	events: Arc<Mutex<Vec<CapturedEvent>>>,
}

impl<S: tracing::Subscriber> Layer<S> for Capture {
	fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
		let mut fields = HashMap::new();
		event.record(&mut FieldVisitor {
			fields: &mut fields,
		});
		self.events.lock().unwrap().push(CapturedEvent {
			level: *event.metadata().level(),
			fields,
		});
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

/// Run `f` with a thread-local subscriber that captures every emitted
/// tracing event, then return the captured set.
pub(crate) fn run_with_capture<F: FnOnce()>(f: F) -> Vec<CapturedEvent> {
	let cap = Capture::default();
	let events = cap.events.clone();
	let subscriber = Registry::default().with(cap);
	tracing::subscriber::with_default(subscriber, f);
	Arc::try_unwrap(events)
		.map(|m| m.into_inner().unwrap())
		.unwrap_or_default()
}
