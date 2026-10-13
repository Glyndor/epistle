//! A graceful stop. SIGTERM starts a drain: the listeners stop accepting,
//! each connection finishes what it is in the middle of and says goodbye
//! (SMTP `421` once no transaction is open, IMAP `* BYE`), and the process
//! exits once they are all gone or the deadline passes, whichever is first.
//!
//! Without it the runtime was dropped as soon as the signal arrived: an
//! SMTP client in the middle of DATA saw the connection reset, and IMAP
//! clients never got a BYE.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::Notify;

/// The drain shared by the server and every listener.
#[derive(Debug, Default)]
pub struct Drain {
	draining: AtomicBool,
	started: Notify,
	active: AtomicUsize,
	finished: Notify,
}

impl Drain {
	/// A drain that has not started.
	pub fn new() -> Arc<Self> {
		Arc::new(Self::default())
	}

	/// Start draining. Every waiter of [`Drain::started`] wakes.
	pub fn begin(&self) {
		self.draining.store(true, Ordering::SeqCst);
		self.started.notify_waiters();
		if self.active.load(Ordering::SeqCst) == 0 {
			self.finished.notify_waiters();
		}
	}

	/// Whether the drain has started.
	pub fn is_draining(&self) -> bool {
		self.draining.load(Ordering::SeqCst)
	}

	/// Resolve once the drain has started (at once if it already has).
	pub async fn started(&self) {
		loop {
			let notified = self.started.notified();
			tokio::pin!(notified);
			notified.as_mut().enable();
			if self.is_draining() {
				return;
			}
			notified.await;
		}
	}

	/// Count a connection as open until the returned guard drops.
	pub fn track(self: &Arc<Self>) -> Tracked {
		self.active.fetch_add(1, Ordering::SeqCst);
		Tracked(Arc::clone(self))
	}

	/// Wait until no tracked connection is open, at most `deadline`.
	/// Returns how many were still open when it gave up (0 on success).
	pub async fn finished(&self, deadline: Duration) -> usize {
		let wait = async {
			loop {
				let notified = self.finished.notified();
				tokio::pin!(notified);
				notified.as_mut().enable();
				if self.active.load(Ordering::SeqCst) == 0 {
					return;
				}
				notified.await;
			}
		};
		let _ = tokio::time::timeout(deadline, wait).await;
		self.active.load(Ordering::SeqCst)
	}
}

/// An open connection, counted by its [`Drain`] until dropped.
#[derive(Debug)]
pub struct Tracked(Arc<Drain>);

impl Drop for Tracked {
	fn drop(&mut self) {
		if self.0.active.fetch_sub(1, Ordering::SeqCst) == 1 {
			self.0.finished.notify_waiters();
		}
	}
}

/// Await `read` for at most `limit`, unless `drain` starts first: `None`
/// then, so the caller says goodbye. Without a drain this is a plain
/// timeout. Reads on a socket are cancel-safe, so nothing read is lost.
pub async fn or_drain<F: Future>(
	drain: Option<&Drain>,
	limit: Duration,
	read: F,
) -> Option<Result<F::Output, tokio::time::error::Elapsed>> {
	match drain {
		None => Some(tokio::time::timeout(limit, read).await),
		Some(drain) => tokio::select! {
			out = tokio::time::timeout(limit, read) => Some(out),
			() = drain.started() => None,
		},
	}
}

#[cfg(test)]
#[path = "shutdown_tests.rs"]
mod tests;
