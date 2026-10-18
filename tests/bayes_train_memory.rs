//! The memory one remote message can make the corpus hold, to be trained on
//! or to be scored.
//!
//! The largest message the SMTP server accepts is 25 MiB by default. The
//! trainer used to split all of it into tokens before writing a row, so a
//! message of distinct words held a few hundred MiB; it must now work on a
//! window of the text and a capped number of tokens. This file holds a single
//! test at a time (they take a lock) with a counting allocator so nothing else
//! in the process moves the peak. It needs no database: the pool points at a closed port and the
//! training stops at the first statement, after the tokens exist.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use epistle::antispam::corpus::BayesStore;

static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

struct Counting;

// SAFETY: every call is forwarded unchanged to the system allocator; the
// counters only observe the sizes.
unsafe impl GlobalAlloc for Counting {
	unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
		// SAFETY: the caller's contract for `alloc` is passed through.
		let ptr = unsafe { System.alloc(layout) };
		if !ptr.is_null() {
			let now = CURRENT.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
			PEAK.fetch_max(now, Ordering::Relaxed);
		}
		ptr
	}

	unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
		CURRENT.fetch_sub(layout.size(), Ordering::Relaxed);
		// SAFETY: `ptr` and `layout` come from a matching `alloc`.
		unsafe { System.dealloc(ptr, layout) }
	}

	unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
		// SAFETY: the caller's contract for `realloc` is passed through.
		let moved = unsafe { System.realloc(ptr, layout, new_size) };
		if !moved.is_null() {
			if new_size >= layout.size() {
				let now = CURRENT.fetch_add(new_size - layout.size(), Ordering::Relaxed)
					+ (new_size - layout.size());
				PEAK.fetch_max(now, Ordering::Relaxed);
			} else {
				CURRENT.fetch_sub(layout.size() - new_size, Ordering::Relaxed);
			}
		}
		moved
	}
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// 25 MiB of distinct words: about 2.6 million tokens.
fn largest_message() -> String {
	let mut text = String::with_capacity(25 * 1024 * 1024);
	let mut n = 0u32;
	while text.len() + 11 <= 25 * 1024 * 1024 {
		text.push_str(&format!("wd{n:07x} "));
		n += 1;
	}
	text
}

/// One measurement at a time: the counters are the whole process's.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn the_largest_message_does_not_make_the_trainer_hold_its_tokens() {
	let _serial = SERIAL.lock().await;
	let text = largest_message();
	let pool = sqlx::postgres::PgPoolOptions::new()
		.acquire_timeout(std::time::Duration::from_millis(500))
		.connect_lazy("postgres://nobody@127.0.0.1:1/none")
		.expect("lazy pool");
	let store = BayesStore::with_key(pool, [7u8; 32]);

	let before = CURRENT.load(Ordering::Relaxed);
	PEAK.store(before, Ordering::Relaxed);
	let outcome = store.train("memory-probe", &text, true).await;
	let growth = PEAK.load(Ordering::Relaxed).saturating_sub(before);

	assert!(outcome.is_err(), "the closed port must stop the training");
	assert!(
		growth <= 8 * 1024 * 1024,
		"training a 25 MiB message grew the heap by {} MiB",
		growth / (1024 * 1024)
	);
}

/// Scoring runs inline in the SMTP session of an unauthenticated sender, so
/// the same message must not make it tokenize, hash and look up all of it.
#[tokio::test]
async fn the_largest_message_does_not_make_the_scorer_hold_its_tokens() {
	let _serial = SERIAL.lock().await;
	let text = largest_message();
	let pool = sqlx::postgres::PgPoolOptions::new()
		.acquire_timeout(std::time::Duration::from_millis(500))
		.connect_lazy("postgres://nobody@127.0.0.1:1/none")
		.expect("lazy pool");
	let store = BayesStore::with_key(pool, [7u8; 32]);

	let before = CURRENT.load(Ordering::Relaxed);
	PEAK.store(before, Ordering::Relaxed);
	let outcome = store.score("memory-probe", &text).await;
	let growth = PEAK.load(Ordering::Relaxed).saturating_sub(before);

	assert!(outcome.is_err(), "the closed port must stop the scoring");
	assert!(
		growth <= 8 * 1024 * 1024,
		"scoring a 25 MiB message grew the heap by {} MiB",
		growth / (1024 * 1024)
	);
}

/// The path the SMTP server takes: bytes, not text. A message that is not
/// valid UTF-8 (any binary attachment) must not be decoded whole.
#[tokio::test]
async fn the_largest_message_does_not_make_the_smtp_scoring_path_copy_it() {
	let _serial = SERIAL.lock().await;
	let mut raw = largest_message().into_bytes();
	raw[0] = 0xff;
	let pool = sqlx::postgres::PgPoolOptions::new()
		.acquire_timeout(std::time::Duration::from_millis(500))
		.connect_lazy("postgres://nobody@127.0.0.1:1/none")
		.expect("lazy pool");
	let store = BayesStore::with_key(pool, [7u8; 32]);

	let before = CURRENT.load(Ordering::Relaxed);
	PEAK.store(before, Ordering::Relaxed);
	let outcome = store.score_message("memory-probe", &raw).await;
	let growth = PEAK.load(Ordering::Relaxed).saturating_sub(before);

	assert!(outcome.is_err(), "the closed port must stop the scoring");
	assert!(
		growth <= 8 * 1024 * 1024,
		"scoring 25 MiB of bytes grew the heap by {} MiB",
		growth / (1024 * 1024)
	);
}
