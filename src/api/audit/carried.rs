//! The audit line of a change that is written on a blocking thread.
//!
//! A write of the management API runs in `spawn_blocking`: the rules read
//! files and take locks. A task of that kind is not cancelled when the
//! request that started it is dropped (the client went away), so the change
//! is made whatever happens to the handler, and the line that records it has
//! to be written on the same thread, right after the commit. A line written
//! by the handler after `.await` is lost when the future is dropped between
//! the two.
//!
//! A blocking thread has neither the subscriber nor the span of the request:
//! [`Carried`] takes both on the handler's side and puts them back around the
//! line.

/// The subscriber and the span of the request that started a blocking write.
pub struct Carried {
	dispatch: tracing::Dispatch,
	span: tracing::Span,
}

impl Carried {
	/// The subscriber and span in force on this thread.
	pub fn capture() -> Self {
		Self {
			dispatch: tracing::dispatcher::get_default(Clone::clone),
			span: tracing::Span::current(),
		}
	}

	/// Run `emit` with the subscriber and span that were captured.
	pub fn run<R>(&self, emit: impl FnOnce() -> R) -> R {
		tracing::dispatcher::with_default(&self.dispatch, || self.span.in_scope(emit))
	}
}
