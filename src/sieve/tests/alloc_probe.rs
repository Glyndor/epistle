//! A counting allocator for the tests that pin how much memory a piece of
//! the interpreter may reserve while it works on big input.
//!
//! It counts only on a thread that asked to be measured, so the other tests
//! running beside it do not disturb the numbers.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
	/// `(live bytes, highest live bytes)` on a thread being measured.
	static LIVE: Cell<Option<(usize, usize)>> = const { Cell::new(None) };
}

fn grow(bytes: usize) {
	let _ = LIVE.try_with(|cell| {
		if let Some((live, peak)) = cell.get() {
			let live = live + bytes;
			cell.set(Some((live, peak.max(live))));
		}
	});
}

fn shrink(bytes: usize) {
	let _ = LIVE.try_with(|cell| {
		if let Some((live, peak)) = cell.get() {
			cell.set(Some((live.saturating_sub(bytes), peak)));
		}
	});
}

struct Probe;

// SAFETY: every call is forwarded unchanged to the system allocator; the
// counting only reads and writes a thread-local `Cell`.
unsafe impl GlobalAlloc for Probe {
	unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
		let ptr = unsafe { System.alloc(layout) };
		if !ptr.is_null() {
			grow(layout.size());
		}
		ptr
	}

	unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
		let ptr = unsafe { System.alloc_zeroed(layout) };
		if !ptr.is_null() {
			grow(layout.size());
		}
		ptr
	}

	unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
		unsafe { System.dealloc(ptr, layout) };
		shrink(layout.size());
	}

	unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
		let new = unsafe { System.realloc(ptr, layout, new_size) };
		if !new.is_null() {
			shrink(layout.size());
			grow(new_size);
		}
		new
	}
}

#[global_allocator]
static PROBE: Probe = Probe;

/// Run `work` and say how many bytes it held at once, at most, on this
/// thread: what it allocated and had not yet freed.
pub(in super::super) fn peak_bytes<T>(work: impl FnOnce() -> T) -> (T, usize) {
	LIVE.with(|cell| cell.set(Some((0, 0))));
	let out = work();
	let peak = LIVE.with(|cell| cell.take()).map_or(0, |(_, peak)| peak);
	(out, peak)
}
