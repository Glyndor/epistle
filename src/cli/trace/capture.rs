//! Test-only tracing event capture.
//!
//! `src/config/validate/tests/base.rs` and `serve_tasks_tests.rs` both need to assert that a
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

#[derive(Clone, Default)]
pub(crate) struct Capture {
	pub(crate) events: Arc<Mutex<Vec<CapturedEvent>>>,
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

/// A process-wide subscriber that records nothing and answers every callsite
/// with `Interest::sometimes()`.
///
/// `tracing` caches each callsite's interest, and two threads rebuilding that
/// cache at once race: the last write wins, and a thread that took its
/// snapshot before a test's scoped subscriber existed can store `never`. The
/// test then misses its own event (measured about once in five suite runs).
/// With this subscriber installed as the global default every snapshot
/// contains it, so no rebuild can store `never` and each event is checked
/// against the live scoped subscriber.
struct KeepCallsitesLive;

impl tracing::Subscriber for KeepCallsitesLive {
	fn register_callsite(
		&self,
		_metadata: &'static tracing::Metadata<'static>,
	) -> tracing::subscriber::Interest {
		tracing::subscriber::Interest::sometimes()
	}
	fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
		false
	}
	fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
		tracing::span::Id::from_u64(1)
	}
	fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}
	fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}
	fn event(&self, _event: &tracing::Event<'_>) {}
	fn enter(&self, _span: &tracing::span::Id) {}
	fn exit(&self, _span: &tracing::span::Id) {}
}

/// Install [`KeepCallsitesLive`] once per test process. Every test that
/// asserts on a captured event calls this before installing its own
/// subscriber.
pub(crate) fn keep_callsites_live() {
	static ONCE: std::sync::Once = std::sync::Once::new();
	ONCE.call_once(|| {
		let _ = tracing::subscriber::set_global_default(KeepCallsitesLive);
	});
}

/// Run `f` with a thread-local subscriber that captures every emitted
/// tracing event, then return the captured set.
pub(crate) fn run_with_capture<F: FnOnce()>(f: F) -> Vec<CapturedEvent> {
	keep_callsites_live();
	let cap = Capture::default();
	let events = cap.events.clone();
	let subscriber = Registry::default().with(cap);
	tracing::subscriber::with_default(subscriber, f);
	std::mem::take(&mut *events.lock().unwrap())
}

#[cfg(test)]
mod tests {
	use std::sync::Mutex;

	/// `tracing` rebuilds every callsite's interest by upgrading each live
	/// dispatcher, from whichever thread registers a new callsite. A rebuild
	/// that overlaps the end of a capture still holds the capture's
	/// subscriber, so the recorded events must not depend on being the
	/// last owner of it. Holding a clone of the dispatcher stands in for
	/// that rebuild.
	#[test]
	fn events_survive_a_dispatcher_held_past_the_capture() {
		let held = Mutex::new(None);
		let events = super::run_with_capture(|| {
			tracing::warn!(probe = "kept", "probe");
			*held.lock().unwrap() = Some(tracing::dispatcher::get_default(Clone::clone));
		});
		assert_eq!(
			events.len(),
			1,
			"the event recorded while another holder kept the subscriber alive was lost"
		);
		drop(held);
	}
}
