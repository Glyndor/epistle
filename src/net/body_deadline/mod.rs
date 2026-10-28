//! A bound on how long a client may take to send a request body.
//!
//! The server limits how long a request head may take, but a body that
//! trickles in a byte at a time would otherwise hold its connection and its
//! handler for as long as the client likes. The clock of a body starts when
//! the handler first polls it, so time spent before the handler reads (a
//! queue, a sign-in check) is not charged to the client, and data that is
//! already there is never refused. From then on the body has an absolute
//! deadline, proportional to the length the request declares, and it must
//! keep up with a minimum rate over each window of time: at the end of a
//! window the octets received in it must be at least the rate times the
//! time it took, and a new window starts. Octets sent in a burst therefore
//! pay for the window they arrive in and no later one, so a client that
//! sends a burst and goes quiet is cut within two windows, not at the
//! deadline. A body that is behind either bound while the handler waits for
//! more ends with an error the handler sees as a failed read.
//!
//! Known limit: the bounds are only checked when the handler waits for more
//! data. A handler that reads a frame, then stops polling for longer than a
//! window and comes back finds the window over; data the socket already
//! holds is not read until the next poll, so it can be charged as late. No
//! handler streams a body today (they use extractors that poll in a loop).

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::Body;
use hyper::body::{Body as HttpBody, Frame, SizeHint};
use tokio::time::{Instant, Sleep};

/// The least time a client gets to send one whole request body, and the time
/// a body of unknown length gets.
pub const BODY_READ_DEADLINE: Duration = Duration::from_secs(15 * 60);

/// The most time a client gets to send one whole request body, however long
/// it declares it is.
pub const BODY_DEADLINE_CEILING: Duration = Duration::from_secs(45 * 60);

/// The window over which a body must keep up with the minimum rate.
pub const BODY_RATE_WINDOW: Duration = Duration::from_secs(15);

/// The slowest average a body may arrive at over each window, in octets per
/// second. It also sets the deadline of a body that declares its
/// length: that many octets at this rate, between the two bounds above.
pub const BODY_MIN_RATE: u64 = 1024;

/// A body that took too long to arrive.
#[derive(Debug)]
pub struct BodyTooSlow;

impl std::fmt::Display for BodyTooSlow {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("request body arrived too slowly")
	}
}

impl std::error::Error for BodyTooSlow {}

/// The bounds a body is held to.
#[derive(Debug, Clone, Copy)]
pub struct Bounds {
	/// Time allowed for a body of unknown or small length.
	pub deadline: Duration,
	/// Time allowed for the largest body.
	pub ceiling: Duration,
	/// Length of the window the minimum rate is checked over.
	pub window: Duration,
	/// Octets per second the body must average over each window.
	pub min_rate: u64,
}

impl Default for Bounds {
	fn default() -> Self {
		Bounds {
			deadline: BODY_READ_DEADLINE,
			ceiling: BODY_DEADLINE_CEILING,
			window: BODY_RATE_WINDOW,
			min_rate: BODY_MIN_RATE,
		}
	}
}

/// Wrap the body of `request` so it is held to `bounds`.
pub fn bound(request: axum::extract::Request, bounds: Bounds) -> axum::extract::Request {
	request.map(|body| {
		if HttpBody::is_end_stream(&body) {
			body
		} else {
			Body::new(Bounded::new(body, bounds))
		}
	})
}

/// [`bound`] under the default [`Bounds`], for `axum::middleware::map_request`.
pub async fn bound_default(request: axum::extract::Request) -> axum::extract::Request {
	bound(request, Bounds::default())
}

impl Bounds {
	/// The time a body that declares `length` octets gets, if it declares any.
	pub fn deadline_for(&self, length: Option<u64>) -> Duration {
		let proportional = Duration::from_secs(length.unwrap_or(0) / self.min_rate.max(1));
		proportional.clamp(self.deadline, self.ceiling.max(self.deadline))
	}
}

struct Bounded {
	inner: Body,
	bounds: Bounds,
	deadline: Duration,
	/// Set by the first poll.
	started: Option<Instant>,
	/// Start of the current window.
	window_start: Option<Instant>,
	/// Octets received in the current window.
	window_bytes: u64,
	timer: Option<Pin<Box<Sleep>>>,
}

impl Bounded {
	fn new(inner: Body, bounds: Bounds) -> Self {
		let deadline = bounds.deadline_for(HttpBody::size_hint(&inner).exact());
		Bounded {
			inner,
			bounds,
			deadline,
			started: None,
			window_start: None,
			window_bytes: 0,
			timer: None,
		}
	}

	/// Close the current window if it is over: `false` when the body fell
	/// short of the minimum rate in it.
	fn keeps_up(&mut self, now: Instant) -> bool {
		let Some(start) = self.window_start else {
			return true;
		};
		let elapsed = now.saturating_duration_since(start);
		if elapsed < self.bounds.window {
			return true;
		}
		let needed = self.bounds.min_rate.saturating_mul(elapsed.as_secs());
		self.window_start = Some(now);
		let received = std::mem::take(&mut self.window_bytes);
		received >= needed
	}

	/// The instant the handler must have been given more octets by.
	fn due(&self, started: Instant) -> Instant {
		let window_end = self.window_start.unwrap_or(started) + self.bounds.window;
		window_end.min(started + self.deadline)
	}
}

impl HttpBody for Bounded {
	type Data = hyper::body::Bytes;
	type Error = axum::Error;

	fn poll_frame(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
	) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
		let this = &mut *self;
		let now = Instant::now();
		let started = *this.started.get_or_insert(now);
		this.window_start.get_or_insert(now);
		match Pin::new(&mut this.inner).poll_frame(cx) {
			Poll::Ready(Some(Ok(frame))) => {
				if let Some(data) = frame.data_ref() {
					this.window_bytes += data.len() as u64;
				}
				Poll::Ready(Some(Ok(frame)))
			}
			Poll::Ready(other) => Poll::Ready(other),
			Poll::Pending => {
				// Only a body the handler is waiting on can be too slow.
				if now >= started + this.deadline || !this.keeps_up(now) {
					return Poll::Ready(Some(Err(axum::Error::new(BodyTooSlow))));
				}
				let due = this.due(started);
				let timer = this
					.timer
					.get_or_insert_with(|| Box::pin(tokio::time::sleep_until(due)));
				timer.as_mut().reset(due);
				if timer.as_mut().poll(cx).is_ready() {
					// The timer fired between the check and now: look again.
					cx.waker().wake_by_ref();
				}
				Poll::Pending
			}
		}
	}

	fn is_end_stream(&self) -> bool {
		self.inner.is_end_stream()
	}

	fn size_hint(&self) -> SizeHint {
		self.inner.size_hint()
	}
}

#[cfg(test)]
mod tests;
