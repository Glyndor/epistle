//! A bound on how long a client may take to send a request body.
//!
//! The server limits how long a request head may take, but a body that
//! trickles in a byte at a time would otherwise hold its connection and its
//! handler for as long as the client likes. A body here has an absolute
//! deadline from the moment the handler starts reading it, and after a short
//! grace it must also keep up with a minimum rate. A body that falls behind
//! either bound ends with an error the handler sees as a failed read.

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::Body;
use hyper::body::{Body as HttpBody, Frame, SizeHint};
use tokio::time::{Instant, Sleep};

/// The most time a client gets to send one whole request body.
pub const BODY_READ_DEADLINE: Duration = Duration::from_secs(15 * 60);

/// How long a body may go before the minimum rate applies.
pub const BODY_RATE_GRACE: Duration = Duration::from_secs(10);

/// The slowest average a body may arrive at once the grace has passed, in
/// octets per second.
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
	/// Time allowed for the whole body.
	pub deadline: Duration,
	/// Time before the minimum rate applies.
	pub grace: Duration,
	/// Octets per second the body must average after the grace.
	pub min_rate: u64,
}

impl Default for Bounds {
	fn default() -> Self {
		Bounds {
			deadline: BODY_READ_DEADLINE,
			grace: BODY_RATE_GRACE,
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

struct Bounded {
	inner: Body,
	bounds: Bounds,
	started: Instant,
	received: u64,
	timer: Pin<Box<Sleep>>,
}

impl Bounded {
	fn new(inner: Body, bounds: Bounds) -> Self {
		let started = Instant::now();
		let timer = Box::pin(tokio::time::sleep_until(started + bounds.grace));
		Bounded {
			inner,
			bounds,
			started,
			received: 0,
			timer,
		}
	}

	/// The instant the body must have more octets by, given what arrived.
	fn due(&self) -> Instant {
		let rate = self.bounds.min_rate.max(1);
		let needed = Duration::from_secs(self.received / rate);
		let rate_due = self.started + self.bounds.grace.max(needed);
		rate_due.min(self.started + self.bounds.deadline)
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
		if Instant::now() >= this.due() {
			return Poll::Ready(Some(Err(axum::Error::new(BodyTooSlow))));
		}
		match Pin::new(&mut this.inner).poll_frame(cx) {
			Poll::Ready(Some(Ok(frame))) => {
				if let Some(data) = frame.data_ref() {
					this.received += data.len() as u64;
				}
				Poll::Ready(Some(Ok(frame)))
			}
			Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(error))),
			Poll::Ready(None) => Poll::Ready(None),
			Poll::Pending => {
				let due = this.due();
				this.timer.as_mut().reset(due);
				if this.timer.as_mut().poll(cx).is_ready() {
					return Poll::Ready(Some(Err(axum::Error::new(BodyTooSlow))));
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
#[path = "body_deadline_tests.rs"]
mod tests;
