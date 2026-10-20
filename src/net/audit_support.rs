//! Test gates for the preauth deadline audit.
//!
//! A [`Gate`] wraps one half of an in-memory `tokio::io::duplex` pair and
//! lets a test force `Poll::Pending` on either `poll_write` or `poll_flush`
//! of the stream the server sees. The server keeps using the transport
//! while the deadline elapses, so any path that bypasses the bounded
//! writer shows up as a task that stays alive past the deadline.
//!
//! Test-only: not compiled into release builds.

use std::{
	io,
	pin::Pin,
	sync::{
		Arc, Mutex,
		atomic::{AtomicBool, AtomicU8, Ordering},
	},
	task::{Context, Poll, Waker},
	time::Duration,
};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, DuplexStream, ReadBuf};

/// 1 = block `poll_write`; 2 = block `poll_flush`.
const BLOCK_WRITE: u8 = 1;
const BLOCK_FLUSH: u8 = 2;

/// Knobs a test holds onto to drive the [`Gate`].
#[derive(Default)]
pub struct Control {
	mode: AtomicU8,
	waiting: AtomicBool,
	dropped: AtomicBool,
	wake: Mutex<Option<Waker>>,
}

impl Control {
	/// Ask the gate to return `Poll::Pending` from `poll_write` (1) or
	/// `poll_flush` (2). Any other `mode` value disables blocking.
	pub fn block(&self, mode: u8) {
		self.waiting.store(false, Ordering::SeqCst);
		self.mode.store(mode, Ordering::SeqCst);
	}

	/// Clear the blocking mode and wake any task that was parked on it.
	pub fn release(&self) {
		self.mode.store(0, Ordering::SeqCst);
		if let Some(waker) = self.wake.lock().unwrap().take() {
			waker.wake();
		}
	}

	/// Whether the server-side gate has been dropped, releasing the
	/// transport for a follow-up connection. Used to assert the listener
	/// slot is free after the deadline fires.
	pub fn was_dropped(&self) -> bool {
		self.dropped.load(Ordering::SeqCst)
	}

	fn pending(&self, mode: u8, cx: &Context<'_>) -> bool {
		if self.mode.load(Ordering::SeqCst) != mode {
			return false;
		}
		self.waiting.store(true, Ordering::SeqCst);
		*self.wake.lock().unwrap() = Some(cx.waker().clone());
		true
	}
}

/// One half of an in-memory duplex pair, with write/flush blocking.
pub struct Gate {
	io: DuplexStream,
	/// Shared handle a test drives to block writes or flushes.
	pub control: Arc<Control>,
}

impl Gate {
	/// Build a paired `(client, gate, control)` triple. `client` is a
	/// plain `DuplexStream`; `gate` is the server-side wrapper, and
	/// `control` is the shared handle a test drives.
	pub fn pair() -> (DuplexStream, Self, Arc<Control>) {
		let (client, io) = tokio::io::duplex(8192);
		let control = Arc::new(Control::default());
		(
			client,
			Self {
				io,
				control: control.clone(),
			},
			control,
		)
	}
}

impl Drop for Gate {
	fn drop(&mut self) {
		self.control.dropped.store(true, Ordering::SeqCst);
	}
}

impl AsyncRead for Gate {
	fn poll_read(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &mut ReadBuf<'_>,
	) -> Poll<io::Result<()>> {
		Pin::new(&mut self.io).poll_read(cx, buf)
	}
}

impl AsyncWrite for Gate {
	fn poll_write(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &[u8],
	) -> Poll<io::Result<usize>> {
		if self.control.pending(BLOCK_WRITE, cx) {
			return Poll::Pending;
		}
		Pin::new(&mut self.io).poll_write(cx, buf)
	}

	fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		if self.control.pending(BLOCK_FLUSH, cx) {
			return Poll::Pending;
		}
		Pin::new(&mut self.io).poll_flush(cx)
	}

	fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		Pin::new(&mut self.io).poll_shutdown(cx)
	}
}

/// Yield repeatedly so the runtime runs every parked future. The audit
/// tests block a single async operation; a few rounds of `yield_now`
/// are enough for it to register as `waiting` on the [`Control`].
pub async fn settle() {
	for _ in 0..100 {
		tokio::task::yield_now().await;
	}
}

/// Read the bytes the server emits on connect, then yield so the
/// runtime settles.
pub async fn greeting(client: &mut DuplexStream) {
	let mut buf = [0u8; 8192];
	assert!(client.read(&mut buf).await.expect("greeting") > 0);
	settle().await;
}

/// Advance the paused clock by `delay` and assert the server task ended
/// on or before the deadline, releasing the transport along the way.
pub async fn cut(
	task: tokio::task::JoinHandle<io::Result<()>>,
	ctl: Arc<Control>,
	delay: Duration,
) {
	settle().await;
	assert!(
		ctl.waiting.load(Ordering::SeqCst),
		"probe did not reach the blocked operation"
	);
	assert!(!task.is_finished(), "server ended before the deadline");
	tokio::time::advance(delay).await;
	settle().await;
	let ended = task.is_finished();
	if !ended {
		task.abort();
	}
	let _ = task.await;
	assert!(ended, "server remained alive beyond the preauth deadline");
	assert!(ctl.was_dropped(), "transport retained");
}
